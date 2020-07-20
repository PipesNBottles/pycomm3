from functools import wraps
import logging
import os
from typing import Union, List, Tuple, Optional
from functools import wraps

from pycomm3.custom_exceptions import DataError, CommError, RequestError

from pycomm3.tag import Tag
from pycomm3.bytes_ import Pack, Unpack
from pycomm3.const import (TagService, EXTENDED_SYMBOL, PATH_SEGMENTS, CLASS_TYPE,
                    INSTANCE_TYPE, ConnectionManagerInstance, PRIORITY, ClassCode, DataType,
                    TIMEOUT_MULTIPLIER, TIMEOUT_TICKS, TRANSPORT_CLASS, PRODUCT_TYPES, VENDORS, STATES,
                    MICRO800_PREFIX, READ_RESPONSE_OVERHEAD, MULTISERVICE_READ_OVERHEAD, MSG_ROUTER_PATH,
                    ConnectionManagerService, CommonService, SUCCESS, INSUFFICIENT_PACKETS, BASE_TAG_BIT,
                    MIN_VER_INSTANCE_IDS, SEC_TO_US, KEYSWITCH, TEMPLATE_MEMBER_INFO_LEN, EXTERNAL_ACCESS,
                    DataTypeSize, MIN_VER_EXTERNAL_ACCESS)
from pycomm3.packets import REQUEST_MAP, RequestPacket, DataFormatType, request_path
from pycomm3.socket_ import Socket
from pycomm3.utils.utils import (_pack_structure, _bit_request, writable_value, _get_array_index,
                                _tag_return_size, _strip_array, _parse_connection_path)


logging.basicConfig(level=logging.DEBUG)


AtomicType = Union[int, float, bool, str]
TagType = Union[AtomicType, List[AtomicType]]
ReturnType = Union[Tag, List[Tag]]

def with_forward_open(func):
    """Decorator to ensure a forward open request has been completed with the plc"""

    @wraps(func)
    def wrapped(self, *args, **kwargs):
        opened = False
        if not self._forward_open():
            if self.attribs['extended forward open']:
                logger = logging.getLogger('pycomm3.clx.LogixDriver')
                logger.info('Extended Forward Open failed, attempting standard Forward Open.')
                self.attribs['extended forward open'] = False
                if self._forward_open():
                    opened = True
        else:
            opened = True

        if not opened:
            msg = f'Target did not connected. {func.__name__} will not be executed.'
            raise DataError(msg)
        return func(self, *args, **kwargs)

    return wrapped


class CipBase:

    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())

    _sequence_number = 1
    _sock = None
    _session = 0
    _connection_opened = False
    _target_cid = None
    _target_is_connected = False
    _info = {}
    _cache = None
    _data_types = {}
    _tags = {}
    use_instance_ids = True

    def __init__(self, path=None, legacy=False, micro800=False, large_packets=True):
        ip, _path = _parse_connection_path(path)
        self._micro800 = micro800
        self._legacy = legacy

        self.attribs = {
        'context': b'_pycomm_',
        'protocol version': b'\x01\x00',
        'rpi': 5000,
        'port': 0xAF12,  # 44818
        'timeout': 10,
        'ip address': ip,
        # is cip_path the right term?  or request_path? or something else?
        'cip_path': _path[1:],  # leave out the len, we sometimes add to the path later
        'option': 0,
        'cid': b'\x27\x04\x19\x71',
        'csn': b'\x27\x04',
        'vid': b'\x09\x10',
        'vsn': b'\x09\x10\x19\x71',
        'name': 'CipBase',
        'extended forward open': large_packets
        }


    @property
    def connection_size(self):
        """CIP connection size, ``4000`` if using Extended Forward Open else ``500``"""
        return 4000 if self.attribs['extended forward open'] else 500
    
    def new_request(self, command: str, *args, **kwargs) -> RequestPacket:
        """
        Creates a new request packet for the given command.
        If the command is invalid, a base :class:`RequestPacket` is created.

        Commands:
            - `send_unit_data`
            - `send_rr_data`
            - `register_session`
            - `unregister_session`
            - `list_identity`
            - `multi_request`
            - `read_tag`
            - `read_tag_fragmented`
            - `write_tag`
            - `write_tag_fragmented`
            - `generic_connected`
            - `generic_unconnected`

        :param command: the service for which a request will be created
        :return: a new request for the command
        """
        cls = REQUEST_MAP[command]
        return cls(self, *args, **kwargs)
    
    @property
    def _sequence(self) -> int:
        """
        Increment and return the sequence id used with connected messages

        :return: The next sequence number
        """
        self._sequence_number += 1

        if self._sequence_number >= 65535:
            self._sequence_number = 1

        return self._sequence_number
    
    def open(self):
        """
        Creates a new Ethernet/IP socket connection to target device and registers a CIP session.

        :return: True if successful, False otherwise
        """
        # handle the socket layer
        if self._connection_opened:
            return
        try:
            if self._sock is None:
                self._sock = Socket()
            self._sock.connect(self.attribs['ip address'], self.attribs['port'])
            self._connection_opened = True
            self.attribs['cid'] = os.urandom(4)
            self.attribs['vsn'] = os.urandom(4)
            if self._register_session() is None:
                self.logger.warning("Session not registered")
                return False
            return True
        except Exception as e:
            raise CommError(e)
    

    def _register_session(self) -> Optional[int]:
        """
        Registers a new CIP session with the target.

        :return: the session id if session registered successfully, else None
        """
        if self._session:
            return self._session

        self._session = 0
        request = self.new_request('register_session')
        request.add(
            self.attribs['protocol version'],
            b'\x00\x00'
        )

        response = request.send()
        if response:
            self._session = response.session
            self.logger.debug(f"Session = {response.session} has been registered.")
            return self._session

        self.logger.warning('Session has not been registered.')
        return None
    

    def _forward_open(self):
        """
        Opens a new connection with the target PLC using the *Forward Open* or *Extended Forward Open* service.

        :return: True if connection is open or was successfully opened, False otherwise
        """

        if self._target_is_connected:
            return True

        if self._session == 0:
            raise CommError("A Session Not Registered Before forward_open.")

        init_net_params = 0b_0100_0010_0000_0000  # CIP Vol 1 - 3-5.5.1.1

        if self.attribs['extended forward open']:
            net_params = Pack.udint((self.connection_size & 0xFFFF) | init_net_params << 16)
        else:
            net_params = Pack.uint((self.connection_size & 0x01FF) | init_net_params)

        route_path = Pack.epath(self.attribs['cip_path'] + MSG_ROUTER_PATH)
        service = ConnectionManagerService.forward_open if not self.attribs['extended forward open'] else ConnectionManagerService.large_forward_open

        forward_open_msg = self._generate_forward_message(net_params)

        response = self.generic_message(
            service=service,
            class_code=ClassCode.connection_manager,
            instance=ConnectionManagerInstance.open_request,
            request_data=b''.join(forward_open_msg),
            route_path=route_path,
            connected=False,
            name='__FORWARD_OPEN__'
        )

        if response:
            self._target_cid = response.value[:4]
            self._target_is_connected = True
            return True
        self.logger.warning(f"forward_open failed - {response.error}")
        return False
    
    def _generate_forward_message(self, net_params):

        if not self._legacy:
            forward_open_msg = [
                PRIORITY,
                TIMEOUT_TICKS,
                b'\x00\x00\x00\x00',
                self.attribs['cid'],
                self.attribs['csn'],
                self.attribs['vid'],
                self.attribs['vsn'],
                TIMEOUT_MULTIPLIER,
                b'\x00\x00\x00',
                b'\x01\x40\x20\x00',
                net_params,
                b'\x01\x40\x20\x00',
                net_params,
                TRANSPORT_CLASS,
            ]
            
        else:
            forward_open_msg = [
            PRIORITY,
            TIMEOUT_TICKS,
            b'\x00\x00\x00\x00',
            self.attribs['cid'],
            self.attribs['csn'],
            self.attribs['vid'],
            self.attribs['vsn'],
            TIMEOUT_MULTIPLIER,
            b'\x00\x00\x00',
            Pack.dint(5000*1000),
            Pack.uint(0x43f8),
            Pack.dint(5000*1000),
            Pack.uint(0x43f8),
            TRANSPORT_CLASS,
        ]
        
        return forward_open_msg

    def close(self):
        """
        Closes the current connection and un-registers the session.
        """
        errs = []
        try:
            if self._target_is_connected:
                self._forward_close()
            if self._session != 0:
                self._un_register_session()
        except Exception as err:
            errs.append(err)
            self.logger.warning(f"Error on close() -> session Err: {err}")

        try:
            if self._sock:
                self._sock.close()
        except Exception as err:
            errs.append(err)
            self.logger.warning(f"close() -> _sock.close Err: {err}")

        self._sock = None
        self._target_is_connected = False
        self._session = 0
        self._connection_opened = False

        if errs:
            raise CommError(' - '.join(str(e) for e in errs))
    
    def _un_register_session(self):
        """
        Un-registers the current session with the target.
        """
        request = self.new_request('unregister_session')
        request.send()
        self._session = None

    def _forward_close(self):
        """ CIP implementation of the forward close message

        Each connection opened with the forward open message need to be closed.
        Refer to ODVA documentation Volume 1 3-5.5.3

        :return: False if any error in the replayed message
        """

        if self._session == 0:
            raise CommError("A session need to be registered before to call forward_close.")

        route_path = Pack.epath(self.attribs['cip_path'] + MSG_ROUTER_PATH, pad_len=True)

        forward_close_msg = [
            PRIORITY,
            TIMEOUT_TICKS,
            self.attribs['csn'],
            self.attribs['vid'],
            self.attribs['vsn'],
        ]

        response = self.generic_message(
            service=ConnectionManagerService.forward_close,
            class_code=ClassCode.connection_manager,
            instance=ConnectionManagerInstance.open_request,
            connected=False,
            route_path=route_path,
            request_data=b''.join(forward_close_msg),
            name='__FORWARD_CLOSE__'
        )
        if response:
            self._target_is_connected = False
            return True

        self.logger.warning(f"forward_close failed - {response.error}")
        return False
    
    def _parse_requested_tags(self, tags):
        requests = {}
        for tag in tags:
            parsed = {}
            try:
                parsed_request = self._parse_tag_request(tag)
                if parsed_request is not None:
                    plc_tag, bit, elements, tag_info = parsed_request
                    parsed['plc_tag'] = plc_tag
                    parsed['bit'] = bit
                    parsed['elements'] = elements
                    parsed['tag_info'] = tag_info
                else:
                    parsed['error'] = 'Failed to parse tag request'
            except RequestError as err:
                parsed['error'] = str(err)

            finally:
                requests[tag] = parsed
        return requests

    
    def generic_message(self,
                        service: bytes,
                        class_code: bytes,
                        instance: bytes,
                        attribute: Optional[bytes] = b'',
                        request_data: Optional[bytes] = b'',
                        data_format: Optional[DataFormatType] = None,
                        name: str = 'generic',
                        connected: bool = True,
                        unconnected_send: bool = False,
                        route_path: Union[bool, bytes] = True) -> Tag:
        """
        Perform a generic CIP message.  Similar to how MSG instructions work in Logix.

        :param service: service code for the request (single byte)
        :param class_code: request object class ID
        :param instance: instance ID of the class
        :param attribute: (optional) attribute ID for the service/class/instance
        :param request_data: (optional) any additional data required for the request
        :param data_format: (reads only) If provided, a read response will automatically be unpacked into the attributes
                            defined, must be a sequence of tuples, (attribute name, data_type).
                            If name is ``None`` or an empty string, it will be ignored. If data-type is an ``int`` it will
                            not be unpacked, but left as ``bytes``.  Data will be returned as a ``dict``.
                            If ``None``, response data will be returned as just ``bytes``.
        :param name:  return ``Tag.tag`` value, arbitrary but can be used for tracking returned Tags
        :param connected: ``True`` if service required a CIP connection (forward open), ``False`` to use UCMM
        :param unconnected_send: (Unconnected Only) wrap service in an UnconnectedSend service
        :param route_path: (Unconnected Only) ``True`` to use current connection route to destination, ``False`` to ignore,
                           Or provide a packed EPATH (``bytes``) route to use.
        :return: a Tag with the result of the request. (Tag.value for writes will be the request_data)
        """

        if connected:
            with_forward_open(lambda _: None)(self)

        _kwargs = {
            'service': service,
            'class_code': class_code,
            'instance': instance,
            'attribute': attribute,
            'request_data': request_data,
            'data_format': data_format,
        }

        if not connected:
            if route_path is True:
                _kwargs['route_path'] = Pack.epath(self.attribs['cip_path'], pad_len=True)
            elif route_path:
                _kwargs['route_path'] = route_path

            _kwargs['unconnected_send'] = unconnected_send

        request = self.new_request('generic_connected' if connected else 'generic_unconnected')

        request.build(**_kwargs)

        response = request.send()

        return Tag(name, response.value, None, error=response.error)
    
    def _send_requests(self, requests):

        def _mkkey(t=None, r=None):
            if t is not None:
                return t['tag'], t['elements']
            else:
                return r.tag, r.elements

        results = {}

        for request in requests:
            try:
                response = request.send()
            except Exception as err:
                self.logger.exception('Error sending request')
                if request.type_ != 'multi':
                    results[_mkkey(r=request)] = Tag(request.tag, None, None, str(err))
                else:
                    for tag in request.tags:
                        results[_mkkey(t=tag)] = Tag(tag['tag'], None, None, str(err))
            else:
                if request.type_ != 'multi':
                    if response:
                        results[_mkkey(r=request)] = Tag(request.tag,
                                                         response.value if request.type_ == 'read' else request.value,
                                                         response.data_type if request.type_ == 'read' else request.data_type,
                                                         response.error)
                    else:
                        results[_mkkey(r=request)] = Tag(request.tag, None, None, response.error)
                else:
                    for tag in response.tags:
                        if tag['service_status'] == SUCCESS:
                            results[_mkkey(t=tag)] = Tag(tag['tag'], tag['value'], tag['data_type'], None)
                        else:
                            results[_mkkey(t=tag)] = Tag(tag['tag'], None, None,
                                                         tag.get('error', 'Unknown Service Error'))
        return results
    
    def _get_tag_info(self, base, attrs) -> Optional[dict]:

        def _recurse_attrs(attrs, data):
            cur, *remain = attrs
            curr_tag = _strip_array(cur)
            if not len(remain):
                return data.get(curr_tag)
            else:
                if curr_tag in data:
                    return _recurse_attrs(remain, data[curr_tag]['data_type']['internal_tags'])
                else:
                    return None
        try:
            data = self._tags.get(_strip_array(base))
            if not len(attrs):
                return data
            else:
                return _recurse_attrs(attrs, data['data_type']['internal_tags'])

        except Exception as err:
            self.logger.exception(f'Failed to lookup tag data for {base}, {attrs}')
            raise
    
    def _parse_tag_request(self, tag: str) -> Optional[Tuple[str, Optional[int], int, dict]]:
        try:
            if tag.endswith('}') and '{' in tag:
                tag, _tmp = tag.split('{')
                elements = int(_tmp[:-1])
            else:
                elements = 1

            bit = None

            base, *attrs = tag.split('.')
            if base.startswith('Program:'):
                base = f'{base}.{attrs.pop(0)}'
            if len(attrs) and attrs[-1].isdigit():
                _bit = attrs.pop(-1)
                bit = ('bit', int(_bit))
                tag = base if not len(attrs) else f"{base}.{''.join(attrs)}"
            tag_info = self._get_tag_info(base, attrs)

            if tag_info['data_type'] == 'DWORD' and elements == 1:
                _tag, idx = _get_array_index(tag)
                tag = f'{_tag}[{idx // 32}]'
                bit = ('bool_array', idx)

            return tag, bit, elements, tag_info

        except Exception:
            # something went wrong parsing the tag path
            raise RequestError('Failed to parse tag request', tag)
    
    def _write_build_requests(self, parsed_tags):
        bit_writes = {}
        if len(parsed_tags) == 1 or self._micro800:
            requests = (self._write_build_single_request(parsed_tags[tag], bit_writes) for tag in parsed_tags)
            return [r for r in requests if r is not None], bit_writes
        else:
            return self._write_build_multi_requests(parsed_tags, bit_writes), bit_writes

    def _write_build_multi_requests(self, parsed_tags, bit_writes):
        requests = []
        current_request = self.new_request('multi_request')
        requests.append(current_request)

        tags_in_requests = set()
        for tag, tag_data in parsed_tags.items():
            if tag_data.get('error') is None and (tag_data['plc_tag'], tag_data['elements']) not in tags_in_requests:
                tags_in_requests.add((tag_data['plc_tag'], tag_data['elements']))

                if _bit_request(tag_data, bit_writes):
                    continue

                tag_data['write_value'] = writable_value(tag_data)

                if len(tag_data['write_value']) > self.connection_size:
                    _request = self.new_request('write_tag_fragmented')
                    _request.add(tag_data['plc_tag'], tag_data['value'], tag_data['elements'], tag_data['tag_info'])
                    requests.append(_request)
                    continue

                try:
                    if not current_request.add_write(tag_data['plc_tag'], tag_data['write_value'], tag_data['elements'],
                                                     tag_data['tag_info']):
                        current_request = self.new_request('multi_request')
                        requests.append(current_request)
                        current_request.add_write(tag_data['plc_tag'], tag_data['write_value'], tag_data['elements'],
                                                  tag_data['tag_info'])

                except RequestError:
                    self.logger.exception(f'Failed to build request for {tag} - skipping')
                    continue

        if bit_writes:
            for tag in bit_writes:
                try:
                    value = bit_writes[tag]['or_mask'], bit_writes[tag]['and_mask']
                    if not current_request.add_write(tag, value, tag_info=bit_writes[tag]['tag_info'], bits_write=True):
                        current_request = self.new_request('multi_request')
                        requests.append(current_request)
                        current_request.add_write(tag, value, tag_info=bit_writes[tag]['tag_info'], bits_write=True)
                except RequestError:
                    self.logger.exception(f'Failed to build request for {tag} - skipping')
                    continue

        return (r for r in requests if (r.type_ == 'multi' and r.tags) or r.type_ == 'write')

    def _write_build_single_request(self, parsed_tag, bit_writes):
        if parsed_tag.get('error') is None:
            if not _bit_request(parsed_tag, bit_writes):
                parsed_tag['write_value'] = writable_value(parsed_tag)
                if len(parsed_tag['write_value']) > self.connection_size:
                    request = self.new_request('write_tag_fragmented')
                else:
                    request = self.new_request('write_tag')

                request.add(parsed_tag['plc_tag'], parsed_tag['write_value'], parsed_tag['elements'],
                            parsed_tag['tag_info'])
                return request
            else:
                try:
                    tag = parsed_tag['plc_tag']
                    value = bit_writes[tag]['or_mask'], bit_writes[tag]['and_mask']
                    request = self.new_request('write_tag')
                    request.add(tag, value, tag_info=bit_writes[tag]['tag_info'], bits_write=True)
                    return request
                except RequestError:
                    self.logger.exception(f'Failed to build request for {tag} - skipping')
                    return None
        else:
            self.logger.error(f'Skipping making request, error: {parsed_tag["error"]}')
            return None
    
    def _read_build_requests(self, parsed_tags):
        if len(parsed_tags) == 1 or self._micro800:
            requests = (self._read_build_single_request(parsed_tags[tag]) for tag in parsed_tags)
            return [r for r in requests if r is not None]
        else:
            return self._read_build_multi_requests(parsed_tags)

    def _read_build_multi_requests(self, parsed_tags):
        """
        creates a list of multi-request packets
        """
        requests = []
        response_size = MULTISERVICE_READ_OVERHEAD
        current_request = self.new_request('multi_request')
        requests.append(current_request)
        tags_in_requests = set()
        for tag, tag_data in parsed_tags.items():
            if tag_data.get('error') is None and (tag_data['plc_tag'], tag_data['elements']) not in tags_in_requests:
                tags_in_requests.add((tag_data['plc_tag'], tag_data['elements']))
                return_size = _tag_return_size(tag_data)
                if return_size > self.connection_size:
                    _request = self.new_request('read_tag_fragmented')
                    _request.add(tag_data['plc_tag'], tag_data['elements'], tag_data['tag_info'])
                    requests.append(_request)
                else:
                    try:
                        return_size += 2  # add 2 bytes for offset list in reply
                        if response_size + return_size < self.connection_size:
                            if current_request.add_read(tag_data['plc_tag'], tag_data['elements'], tag_data['tag_info']):
                                response_size += return_size
                            else:
                                response_size = return_size + MULTISERVICE_READ_OVERHEAD
                                current_request = self.new_request('multi_request')
                                current_request.add_read(tag_data['plc_tag'], tag_data['elements'], tag_data['tag_info'])
                                requests.append(current_request)
                        else:
                            response_size = return_size + MULTISERVICE_READ_OVERHEAD
                            current_request = self.new_request('multi_request')
                            current_request.add_read(tag_data['plc_tag'], tag_data['elements'], tag_data['tag_info'])
                            requests.append(current_request)
                    except RequestError:
                        self.logger.exception(f'Failed to build request for {tag} - skipping')
                        continue
            else:
                self.logger.error(f'Skipping making request for {tag}, error: {tag_data.get("error")}')
                continue

        return (r for r in requests if (r.type_ == 'multi' and r.tags) or r.type_ == 'read')

    def _read_build_single_request(self, parsed_tag):
        """
        creates a single read_tag request packet
        """

        if parsed_tag.get('error') is None:
            return_size = _tag_return_size(parsed_tag)
            if return_size > self.connection_size:
                request = self.new_request('read_tag_fragmented')
            else:
                request = self.new_request('read_tag')

            request.add(parsed_tag['plc_tag'], parsed_tag['elements'], parsed_tag['tag_info'])

            return request

        self.logger.error(f'Skipping making request, error: {parsed_tag["error"]}')
        return None