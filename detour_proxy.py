import asyncio
import logging
import ipaddress
import signal
import sys
import os.path
from contextlib import ExitStack, contextmanager
from enum import IntEnum

import aiosocks


LISTEN_ADDRESS = ('127.0.9.1', 1080)
UPSTREAM_PROXY_ADDRESS = aiosocks.Socks5Addr('127.0.0.1', 1080)
UPSTREAM_PROXY_AUTH = None

WINDOWS_USE_PROACTOR_EVENT_LOOP = True


class SOCKS5AuthType(IntEnum):
    NO_AUTH = 0
    GSSAPI = 1
    USERNAME_PASSWORD = 2
    NO_OFFERS_ACCEPTABLE = 0xff


class SOCKS5Command(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class SOCKS5AddressType(IntEnum):
    IPV4_ADDRESS = 1
    DOMAIN_NAME = 3
    IPV6_ADDRESS = 4


class SOCKS5Reply(IntEnum):
    SUCCESS = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8


@contextmanager
def finally_close(writer: asyncio.StreamWriter):
    """Closes writer on normal context exit and aborts on exception."""
    try:
        yield
    except Exception:
        writer.transport.abort()
        raise
    finally:
        writer.close()


class WithSet(set):
    """A set with a with_this(item) context manager."""
    @contextmanager
    def with_this(self, item):
        if item in self:
            raise KeyError('item {!r} already in set'.format(item))
        self.add(item)
        try:
            yield
        finally:
            self.remove(item)


class UpstreamNetworkError(RuntimeError):
    """Signify a network error in the upstream connection."""


class DetourProxy:

    RELAY_BUFFER_SIZE = 2 ** 12
    DETOUR_TIMEOUT = 3

    def __init__(self, loop, listen_host, listen_port,
                 upstream_addr, upstream_auth=None, detour_whitelist=None):
        self._loop = loop
        self._logger = logging.getLogger('DetourProxy')
        self._upstream_addr = upstream_addr
        self._upstream_auth = upstream_auth
        self._whitelist = detour_whitelist or DetourWhitelist()

        self._connections = WithSet()
        self._server = None
        self._server_task = loop.create_task(asyncio.start_server(
            self._handle_socks5_connection, listen_host, listen_port,
            loop=loop))
        self._server_task.add_done_callback(self._server_done_callback)

    def _server_done_callback(self, fut):
        try:
            self._server = fut.result()
        except asyncio.CancelledError:
            self._logger.debug('start_server() cancelled')
        except Exception as e:
            self._logger.error('Creating server failed with %r', e,
                               exc_info=True)
        else:
            self._logger.info('DetourProxy listening on %r',
                              [s.getsockname() for s in self._server.sockets])

    @property
    def ready_fut(self):
        return self._server_task

    @staticmethod
    def _make_socks5_command_reply(reply: int, addr: str, port: int):
        try:
            ipaddr = ipaddress.ip_address(addr)
        except ValueError:
            b_addr = addr.encode('utf-8')
            b_addr = (bytes((SOCKS5AddressType.DOMAIN_NAME, len(b_addr)))
                      + b_addr)
        else:
            if ipaddr.version == 4:
                b_addr = bytes((SOCKS5AddressType.IPV4_ADDRESS,))
            elif ipaddr.version == 6:
                b_addr = bytes((SOCKS5AddressType.IPV6_ADDRESS,))
            else:
                assert False, 'illegal ipaddress version'
            b_addr += ipaddr.packed
        return bytes((5, reply, 0)) + b_addr + port.to_bytes(2, 'big')

    async def _handle_socks5_connection(self, dreader: asyncio.StreamReader,
                                        dwriter: asyncio.StreamWriter):
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))

        try:  # catch, log and suppress all exceptions in outermost layer
            with ExitStack() as stack:
                stack.enter_context(self._connections.with_this(
                    asyncio.Task.current_task()))
                stack.enter_context(finally_close(dwriter))
                self._logger.debug('%s accepted downstream connection',
                                   log_name)

                # Negotiate incoming SOCKS5 connection
                # Authentication
                buf = await dreader.readexactly(1)  # Version marker
                if buf[0] != 5:
                    raise RuntimeError('%s invalid SOCKS version' % log_name)
                buf = await dreader.readexactly(1)  # number of auth methods
                buf = await dreader.readexactly(buf[0])  # offered auth methods
                if SOCKS5AuthType.NO_AUTH not in buf:
                    self._logger.info('%s did not offer "no auth", offers: %r',
                                      log_name, buf)
                    dwriter.write(
                        bytes((5, SOCKS5AuthType.NO_OFFERS_ACCEPTABLE)))
                    dwriter.write_eof()
                    await dwriter.drain()
                    return
                dwriter.write(bytes((5, SOCKS5AuthType.NO_AUTH)))

                # client command
                buf = await dreader.readexactly(4)  # ver, cmd, rsv, addr_type
                if buf[0] != 5 or buf[2] != 0:
                    raise RuntimeError('%s malformed SOCKS5 command' % log_name)
                cmd = buf[1]
                addr_type = buf[3]
                if addr_type == SOCKS5AddressType.IPV4_ADDRESS:
                    uhost = ipaddress.IPv4Address(
                        await dreader.readexactly(4)).compressed
                elif addr_type == SOCKS5AddressType.IPV6_ADDRESS:
                    uhost = ipaddress.IPv6Address(
                        await dreader.readexactly(16)).compressed
                elif addr_type == SOCKS5AddressType.DOMAIN_NAME:
                    buf = await dreader.readexactly(1)  # address len
                    uhost = (await dreader.readexactly(buf[0])).decode('utf-8')
                else:
                    raise RuntimeError('%s illegal address type' % log_name)
                uport = int.from_bytes(await dreader.readexactly(2), 'big')
                log_name = '{!r} <=> ({!r}, {!r})'.format(
                    dwriter.transport.get_extra_info('peername'),
                    uhost, uport)
                self._logger.debug('%s parsed target address', log_name)
                if cmd != SOCKS5Command.CONNECT:
                    self._logger.info('%s command %r not supported',
                                      log_name, cmd)
                    dwriter.write(self._make_socks5_command_reply(
                        SOCKS5Reply.COMMAND_NOT_SUPPORTED, '0.0.0.0', 0))
                    dwriter.write_eof()
                    await dwriter.drain()
                    return
                self._logger.info('%s received CONNECT command', log_name)

                # determine detour state of host name
                # Since getting and setting detour state is separated quite far,
                # multiple connections to the same host will quite possibly
                # make the state inconsistent. However that does not have much
                # adverse effects on the operation.
                detour_state = self._whitelist.state(uhost)
                if not detour_state[0]:
                    self._logger.info('%s try direct connection', log_name)
                    try:
                        ureader, uwriter = await asyncio.wait_for(
                            asyncio.open_connection(
                                uhost, uport, loop=self._loop,
                                limit=self.RELAY_BUFFER_SIZE),
                            self.DETOUR_TIMEOUT, loop=self._loop)
                    except (OSError, asyncio.TimeoutError) as e:
                        self._logger.info('%s direct connection error: %r',
                                          log_name, e)
                        self._whitelist.add_to_temp_wl(uhost)
                        # continue to making detoured connection
                    else:
                        self._logger.info('%s direct connection successful',
                                          log_name)
                        stack.enter_context(finally_close(uwriter))
                        dwriter.write(self._make_socks5_command_reply(
                            SOCKS5Reply.SUCCESS,
                            *(uwriter.transport.get_extra_info('sockname')[:2])
                        ))
                        try:
                            await self._relay_data(dreader, dwriter,
                                                   ureader, uwriter,
                                                   (uhost, uport))
                        except UpstreamNetworkError as e:
                            self._logger.info('%s direct connection upstream '
                                              'error during relay: %r',
                                              log_name, e.__cause__)
                            self._whitelist.add_to_temp_wl(uhost)
                            raise
                        self._logger.info('%s direct connection completed '
                                          'without error', log_name)
                        # not going to make a detoured connection and try again
                        # because retrying means resending all sent data
                        return
                self._logger.info('%s try detoured connection', log_name)
                try:
                    ureader, uwriter = await aiosocks.open_connection(
                        self._upstream_addr, self._upstream_auth,
                        (uhost, uport), remote_resolve=True, loop=self._loop,
                        limit=self.RELAY_BUFFER_SIZE)
                except (OSError, aiosocks.SocksError) as e:
                    self._logger.info('%s detour connection error: %r',
                                      log_name, e)
                    dwriter.write(self._make_socks5_command_reply(
                        SOCKS5Reply.GENERAL_SOCKS_SERVER_FAILURE,
                        '0.0.0.0', 0))
                    dwriter.write_eof()
                    await dwriter.drain()
                    if detour_state[0] == DetourState.TEMP:
                        self._whitelist.remove_from_temp_wl(detour_state[1])
                    return
                self._logger.info('%s detour connection successful', log_name)
                stack.enter_context(finally_close(uwriter))
                dwriter.write(self._make_socks5_command_reply(
                    SOCKS5Reply.SUCCESS,
                    *uwriter.transport.get_extra_info('sockname')[:2]))
                try:
                    await self._relay_data(dreader, dwriter,
                                           ureader, uwriter,
                                           (uhost, uport))
                except UpstreamNetworkError as e:
                    self._logger.info('%s detoured connection upstream error '
                                      'during relay: %r', log_name, e.__cause__)
                    if detour_state[0] == DetourState.TEMP:
                        self._whitelist.remove_from_temp_wl(detour_state[1])
                    raise
                self._logger.info('%s detoured connection completed without '
                                  'error', log_name)
                if detour_state[0] == DetourState.TEMP:
                    self._whitelist.add_to_perm_wl(detour_state[1])
        except asyncio.CancelledError:
            self._logger.debug('%s cancelled', log_name)
            raise
        except (RuntimeError,
                OSError,
                UpstreamNetworkError,
                ) as e:  # not logging stack trace for normal errors
            self._logger.info('%s %r', log_name, e)
        except Exception as e:
            self._logger.error('%s %r', log_name, e, exc_info=True)
        finally:
            self._logger.debug('%s connection done', log_name)

    async def _relay_data_side(self, reader, writer,
                               log_name, write_is_upstream):
        try:
            while True:
                try:
                    buf = await reader.read(self.RELAY_BUFFER_SIZE)
                except (OSError, aiosocks.SocksError) as e:
                    if not write_is_upstream:
                        raise UpstreamNetworkError from e
                    else:
                        raise
                if not buf:
                    break
                self._logger.debug('%s received data', log_name)
                try:
                    writer.write(buf)
                    await writer.drain()
                except (OSError, aiosocks.SocksError) as e:
                    if write_is_upstream:
                        raise UpstreamNetworkError from e
                    else:
                        raise
                self._logger.debug('%s sent data', log_name)
            self._logger.debug('%s received EOF', log_name)
            try:
                writer.write_eof()
                await writer.drain()
            except (OSError, aiosocks.SocksError) as e:
                if write_is_upstream:
                    raise UpstreamNetworkError from e
                else:
                    raise
            self._logger.debug('%s wrote EOF', log_name)
        except asyncio.CancelledError:
            self._logger.debug('%s cancelled', log_name)
            raise
        except Exception as e:
            self._logger.info('%s got exception: %r', log_name, e)
            raise

    async def _relay_data(self,
                          dreader: asyncio.StreamReader,
                          dwriter: asyncio.StreamWriter,
                          ureader: asyncio.StreamReader,
                          uwriter: asyncio.StreamWriter,
                          uname):
        dname = dwriter.transport.get_extra_info('peername')
        utask = self._loop.create_task(self._relay_data_side(
            dreader, uwriter, '{!r} --> {!r}'.format(dname, uname), True))
        dtask = self._loop.create_task(self._relay_data_side(
            ureader, dwriter, '{!r} <-- {!r}'.format(dname, uname), False))
        gather_task = asyncio.gather(utask, dtask)
        try:
            await gather_task
        except Exception:
            dwriter.transport.abort()
            uwriter.transport.abort()
            dtask.cancel()
            utask.cancel()
            raise

    async def close(self):
        """Terminate the server and all active connections."""
        self._logger.info('DetourProxy closing')
        wait_list = []
        self._server_task.cancel()
        wait_list.append(self._server_task)
        if self._server is not None:
            self._server.close()
            wait_list.append(self._server.wait_closed())
        for conn in self._connections:
            conn.cancel()
            wait_list.append(conn)
        # wait_list.extend(self._connections)
        await asyncio.gather(*wait_list, return_exceptions=True)


class DetourState(IntEnum):
    NOT_IN_LIST = 0  # evaluates to False, others evaluate to True
    TEMP = 1
    PERM = 2
    BUILTIN = 3


class DetourWhitelist:
    def __init__(self):
        self._temp = set()
        self._perm = set()
        self._builtin = set()
        self._logger = logging.getLogger('DetourWhitelist')

    def state(self, addr):
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            addr_to_match = []
            addr_domains = addr
            while addr_domains:
                addr_to_match.append(addr_domains)
                addr_domains = addr_domains.partition('.')[2]
        else:
            addr_to_match = [addr]
        for match_addr in addr_to_match:
            if match_addr in self._builtin:
                self._logger.info('%s in built-in detour list as %s',
                                  addr, match_addr)
                return DetourState.BUILTIN, match_addr
            elif match_addr in self._perm:
                self._logger.info('%s in permanent detour list as %s',
                                  addr, match_addr)
                return DetourState.PERM, match_addr
            elif match_addr in self._temp:
                self._logger.info('%s in temporary detour list as %s',
                                  addr, match_addr)
                return DetourState.TEMP, match_addr
        return DetourState.NOT_IN_LIST, addr

    def add_to_temp_wl(self, addr):
        self._logger.info('Adding %r to temporary whitelist', addr)
        self._temp.add(addr)

    def remove_from_temp_wl(self, addr):
        self._logger.info('Removing %r from temporary whitelist', addr)
        self._temp.discard(addr)

    def add_to_perm_wl(self, addr):
        self._logger.info('Adding %r to permanent whitelist', addr)
        self._perm.add(addr)
        self._temp.discard(addr)

    def load_builtin_wl(self, wl):
        self._builtin.update(wl)

    def print_lists(self):
        temp_list = list(self._temp)
        temp_list.sort()
        perm_list = list(self._perm)
        perm_list.sort()
        print('Temporary Whitelist:')
        for l in temp_list:
            print(l)
        print('Permanent Whitelist:')
        for l in perm_list:
            print(l)


def windows_async_signal_helper(loop, interval=0.2):
    """Schedule a do-nothing regular callback on Windows only.

    This is a workaround for Python Issue 23057 in Windows
    ( https://bugs.python.org/issue23057 ), where signals like
    KeyboardInterrupt will not be delivered in an event loop if nothing
    is happening. A regular callback allows such signals to be
    delivered.
    """
    if sys.platform == 'win32':
        noop_callback(loop, interval)


def noop_callback(loop, delay):
    """Do nothing and schedule to do nothing later."""
    loop.call_later(delay, noop_callback, loop, delay)


def sigterm_handler(sig, frame):
    logging.warning('Received signal %r', sig)
    sys.exit(0)


def relay():
    logging.basicConfig(level=logging.INFO)
    if WINDOWS_USE_PROACTOR_EVENT_LOOP and sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()
    whitelist = DetourWhitelist()
    whitelistfile = os.path.join(os.path.dirname(__file__), 'whitelist.txt')
    try:
        with open(whitelistfile, 'rt') as wl_file:
            whitelist.load_builtin_wl(l.strip() for l in wl_file)
    except OSError as e:
        logging.warning('loading whitelist file failed: %r', e)
    else:
        logging.info('whitelist file loaded')
    proxy = DetourProxy(asyncio.get_event_loop(), *LISTEN_ADDRESS,
                        UPSTREAM_PROXY_ADDRESS, UPSTREAM_PROXY_AUTH, whitelist)
    windows_async_signal_helper(loop)
    try:
        loop.add_signal_handler(signal.SIGINT, sigterm_handler)
        loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
    except NotImplementedError:
        pass
    try:
        loop.run_forever()
    except (SystemExit, KeyboardInterrupt) as e:
        logging.warning('Received %r', e)
        loop.run_until_complete(proxy.close())
    finally:
        whitelist.print_lists()


if __name__ == '__main__':
    relay()
