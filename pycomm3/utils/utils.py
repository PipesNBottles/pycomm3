import socket
import itertools
import re


from pycomm3.bytes_ import Unpack, Pack
from pycomm3.const import (VENDORS, KEYSWITCH, PRODUCT_TYPES, SUCCESS, STATES, READ_RESPONSE_OVERHEAD,
                           PATH_SEGMENTS, BASE_TAG_BIT, DataTypeSize, DataType, PCCC_CT)
from pycomm3.custom_exceptions import DataError, RequestError


def _parse_plc_name(data):
    try:
        name_len = Unpack.uint(data[6:8])
        return data[8: 8 + name_len].decode()
    except Exception as err:
        raise DataError('failed parsing plc name') from err


def _parse_plc_info(data):
    parsed = {k: v for k, v in data.items() if not k.startswith('_')}
    parsed['vendor'] = VENDORS.get(parsed['vendor'], 'UNKNOWN')
    parsed['product_type'] = PRODUCT_TYPES.get(parsed['product_type'], 'UNKNOWN')
    parsed['revision'] = f"{parsed['version_major']}.{parsed['version_minor']}"
    parsed['serial'] = f"{parsed['serial']:08x}"
    parsed['keyswitch'] = KEYSWITCH.get(data['_keyswitch'][0], {}).get(data['_keyswitch'][1], 'UNKNOWN')

    return parsed


def _parse_identity_object(reply):
    vendor = Unpack.uint(reply[:2])
    product_type = Unpack.uint(reply[2:4])
    product_code = Unpack.uint(reply[4:6])
    major_fw = int(reply[6])
    minor_fw = int(reply[7])
    status = f'{Unpack.uint(reply[8:10]):0{16}b}'
    serial_number = f'{Unpack.udint(reply[10:14]):0{8}x}'
    product_name_len = int(reply[14])
    tmp = 15 + product_name_len
    device_type = reply[15:tmp].decode()

    state = Unpack.uint(reply[tmp:tmp + 4]) if reply[tmp:] else -1  # some modules don't return a state

    return {
        'vendor': VENDORS.get(vendor, 'UNKNOWN'),
        'product_type': PRODUCT_TYPES.get(product_type, 'UNKNOWN'),
        'product_code': product_code,
        'version_major': major_fw,
        'version_minor': minor_fw,
        'revision': f'{major_fw}.{minor_fw}',
        'serial': serial_number,
        'device_type': device_type,
        'status': status,
        'state': STATES.get(state, 'UNKNOWN'),
    }


def _parse_structure_makeup_attributes(response):
        """ extract the tags list from the message received"""
        structure = {}

        if response.service_status != SUCCESS:
            structure['Error'] = response.service_status
            return

        attribute = response.data
        idx = 4
        try:
            if Unpack.uint(attribute[idx:idx + 2]) == SUCCESS:
                idx += 2
                structure['object_definition_size'] = Unpack.dint(attribute[idx:idx + 4])
            else:
                structure['Error'] = 'object_definition Error'
                return structure

            idx += 6
            if Unpack.uint(attribute[idx:idx + 2]) == SUCCESS:
                idx += 2
                structure['structure_size'] = Unpack.dint(attribute[idx:idx + 4])
            else:
                structure['Error'] = 'structure Error'
                return structure

            idx += 6
            if Unpack.uint(attribute[idx:idx + 2]) == SUCCESS:
                idx += 2
                structure['member_count'] = Unpack.uint(attribute[idx:idx + 2])
            else:
                structure['Error'] = 'member_count Error'
                return structure

            idx += 4
            if Unpack.uint(attribute[idx:idx + 2]) == SUCCESS:
                idx += 2
                structure['structure_handle'] = Unpack.uint(attribute[idx:idx + 2])
            else:
                structure['Error'] = 'structure_handle Error'
                return structure

            return structure

        except Exception as e:
            raise DataError(e)


def writable_value(parsed_tag):
    if isinstance(parsed_tag['value'], bytes):
        return parsed_tag['value']

    try:
        value = parsed_tag['value']
        elements = parsed_tag['elements']
        data_type = parsed_tag['tag_info']['data_type']

        if elements > 1:
            if len(value) < elements:
                raise RequestError('Insufficient data for requested elements')
            if len(value) > elements:
                value = value[:elements]

        if parsed_tag['tag_info']['tag_type'] == 'struct':
            return _writable_value_structure(value, elements, data_type)
        else:
            pack_func = Pack[data_type]

            if elements > 1:
                return b''.join(pack_func(value[i]) for i in range(elements))
            else:
                return pack_func(value)
    except Exception as err:
        raise RequestError('Unable to create a writable value', err)


def _strip_array(tag):
    if '[' in tag:
        return tag[:tag.find('[')]
    return tag


def _get_array_index(tag):
    if tag.endswith(']') and '[' in tag:
        tag, _tmp = tag.split('[')
        idx = int(_tmp[:-1])
    else:
        idx = 0

    return tag, idx


def _tag_return_size(tag_data):
    tag_info = tag_data['tag_info']
    if tag_info['tag_type'] == 'atomic':
        size = DataTypeSize[tag_info['data_type']]
    else:
        size = tag_info['data_type']['template']['structure_size']

    size = (size * tag_data['elements']) + READ_RESPONSE_OVERHEAD  # account for service overhead

    return size


def _writable_value_structure(value, elements, data_type):
    if elements > 1:
        return b''.join(_pack_structure(val, data_type) for val in value)
    else:
        return _pack_structure(value, data_type)


def _pack_string(value, string_len, struct_size):
    try:
        sint_array = [b'\x00' for _ in range(struct_size-4)]  # 4 for .LEN
        if len(value) > string_len:
            value = value[:string_len]
        for i, s in enumerate(value):
            sint_array[i] = Pack.char(s)
    except Exception as err:
        raise RequestError('Failed to pack string') from err
    return Pack.dint(len(value)) + b''.join(sint_array)


def _pack_structure(value, data_type):
    string_len = data_type.get('string')

    if string_len:
        data = _pack_string(value, string_len, data_type['template']['structure_size'])
    else:
        data = [0 for _ in range(data_type['template']['structure_size'])]
        try:
            # NOTE:  start with bytes(object-definition-size) , then replace sections with offset + data len
            for val, attr in zip(value, data_type['attributes']):
                dtype = data_type['internal_tags'][attr]
                offset = dtype['offset']

                ary = dtype.get('array')
                if dtype['tag_type'] == 'struct':
                    if ary:
                        value_bytes = [_pack_structure(val[i], dtype['data_type']) for i in range(ary)]
                    else:
                        value_bytes = [_pack_structure(val, dtype['data_type']), ]
                else:
                    pack_func = Pack[dtype['data_type']]
                    bit = dtype.get('bit')
                    if bit is not None:
                        if val:
                            data[offset] |= 1 << bit
                        else:
                            data[offset] &= ~(1 << bit)
                        continue

                    if ary:
                        value_bytes = [pack_func(val[i]) for i in range(ary)]
                    else:
                        value_bytes = [pack_func(val), ]

                val_bytes = list(itertools.chain.from_iterable(value_bytes))
                data[offset:offset+len(val_bytes)] = val_bytes

        except Exception as err:
            raise RequestError('Value Invalid for Structure') from err

    return bytes(data)


def _pad(data):
    return data + b'\x00' * (len(data) % 4)  # pad data to 4-byte boundaries


def _bit_request(tag_data, bit_requests):
    if tag_data.get('bit') is None:
        return None

    if tag_data['plc_tag'] not in bit_requests:
        bit_requests[tag_data['plc_tag']] = {'and_mask': 0xFFFFFFFF,
                                             'or_mask': 0x00000000,
                                             'bits': [],
                                             'tag_info': tag_data['tag_info']}

    bits_ = bit_requests[tag_data['plc_tag']]
    typ_, bit = tag_data['bit']
    bits_['bits'].append(bit)

    if typ_ == 'bool_array':
        bit = bit % 32

    if tag_data['value']:
        bits_['or_mask'] |= (1 << bit)
    else:
        bits_['and_mask'] &= ~(1 << bit)

    return True


def _parse_connection_path(path):
    ip, *segments = path.split('/')
    try:
        socket.inet_aton(ip)
    except OSError:
        raise ValueError('Invalid IP Address', ip)
    segments = [_parse_cip_path_segment(s) for s in segments]

    if not segments:
        _path = [Pack.usint(PATH_SEGMENTS['backplane']), b'\x00']  # [] if micro800 else
    elif len(segments) == 1:
        _path = [Pack.usint(PATH_SEGMENTS['backplane']), Pack.usint(segments[0])]
    else:
        pairs = (segments[i:i + 2] for i in range(0, len(segments), 2))
        _path = []
        for port, dest in pairs:
            if isinstance(dest, bytes):
                port |= 1 << 4  # set Extended Link Address bit, CIP Vol 1 C-1.3
                dest_len = len(dest)
                if dest_len % 2:
                    dest += b'\x00'
                _path.extend([Pack.usint(port), Pack.usint(dest_len), dest])
            else:
                _path.extend([Pack.usint(port), Pack.usint(dest)])

    return ip, Pack.epath(b''.join(_path))


def _parse_cip_path_segment(segment: str):
    try:
        if segment.isnumeric():
            return int(segment)
        else:
            tmp = PATH_SEGMENTS.get(segment.lower())
            if tmp:
                return tmp
            else:
                try:
                    socket.inet_aton(segment)
                    return b''.join(Pack.usint(ord(c)) for c in segment)
                except OSError:
                    raise ValueError('Invalid IP Address Segment', segment)
    except Exception:
        raise ValueError(f'Failed to parse path segment', segment)


def _create_tag(name, raw_tag):

    new_tag = {
        'tag_name': name,
        'dim': (raw_tag['symbol_type'] & 0b0110000000000000) >> 13,  # bit 13 & 14, number of array dims
        'instance_id': raw_tag['instance_id'],
        'symbol_address': raw_tag['symbol_address'],
        'symbol_object_address': raw_tag['symbol_object_address'],
        'software_control': raw_tag['software_control'],
        'alias': False if raw_tag['software_control'] & BASE_TAG_BIT else True,
        'external_access': raw_tag['external_access'],
        'dimensions': raw_tag['dimensions']
    }

    if raw_tag['symbol_type'] & 0b_1000_0000_0000_0000:  # bit 15, 1 = struct, 0 = atomic
        template_instance_id = raw_tag['symbol_type'] & 0b_0000_1111_1111_1111
        new_tag['tag_type'] = 'struct'
        new_tag['template_instance_id'] = template_instance_id
    else:
        new_tag['tag_type'] = 'atomic'
        datatype = raw_tag['symbol_type'] & 0b_0000_0000_1111_1111
        new_tag['data_type'] = DataType.get(datatype)
        if datatype == DataType.bool:
            new_tag['bit_position'] = (raw_tag['symbol_type'] & 0b_0000_0111_0000_0000) >> 8

    return new_tag


def legacy_parse_tag(tag):
    t = re.search(r"(?P<file_type>[CT])(?P<file_number>\d{1,3})"
                  r"(:)(?P<element_number>\d{1,3})"
                  r"(.)(?P<sub_element>ACC|PRE|EN|DN|TT|CU|CD|DN|OV|UN|UA)", tag, flags=re.IGNORECASE)
    if t:
        if (1 <= int(t.group('file_number')) <= 255) \
                and (0 <= int(t.group('element_number')) <= 255):
            return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                      'file_number': t.group('file_number'),
                                      'element_number': t.group('element_number'),
                                      'sub_element': PCCC_CT[t.group('sub_element').upper()],
                                      'read_func': b'\xa2',
                                      'write_func': b'\xab',
                                      'address_field': 3}

    t = re.search(r"(?P<file_type>[LFBN])(?P<file_number>\d{1,3})"
                  r"(:)(?P<element_number>\d{1,3})"
                  r"(/(?P<sub_element>\d{1,2}))?",
                  tag, flags=re.IGNORECASE)
    if t:
        if t.group('sub_element') is not None:
            if (1 <= int(t.group('file_number')) <= 255) \
                    and (0 <= int(t.group('element_number')) <= 255) \
                    and (0 <= int(t.group('sub_element')) <= 15):

                return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                          'file_number': t.group('file_number'),
                                          'element_number': t.group('element_number'),
                                          'sub_element': t.group('sub_element'),
                                          'read_func': b'\xa2',
                                          'write_func': b'\xab',
                                          'address_field': 3}
        else:
            if (1 <= int(t.group('file_number')) <= 255) \
                    and (0 <= int(t.group('element_number')) <= 255):

                return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                          'file_number': t.group('file_number'),
                                          'element_number': t.group('element_number'),
                                          'sub_element': t.group('sub_element'),
                                          'read_func': b'\xa2',
                                          'write_func': b'\xab',
                                          'address_field': 2}

    t = re.search(r"(?P<file_type>[IO])(:)(?P<file_number>\d{1,3})"
                  r"(.)(?P<element_number>\d{1,3})"
                  r"(/(?P<sub_element>\d{1,2}))?", tag, flags=re.IGNORECASE)
    if t:
        if t.group('sub_element') is not None:
            if (0 <= int(t.group('file_number')) <= 255) \
                    and (0 <= int(t.group('element_number')) <= 255) \
                    and (0 <= int(t.group('sub_element')) <= 15):

                return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                          'file_number': t.group('file_number'),
                                          'element_number': t.group('element_number'),
                                          'sub_element': t.group('sub_element'),
                                          'read_func': b'\xa2',
                                          'write_func': b'\xab',
                                          'address_field': 3}
        else:
            if (0 <= int(t.group('file_number')) <= 255) \
                    and (0 <= int(t.group('element_number')) <= 255):

                return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                          'file_number': t.group('file_number'),
                                          'element_number': t.group('element_number'),
                                          'read_func': b'\xa2',
                                          'write_func': b'\xab',
                                          'address_field': 2}

    t = re.search(r"(?P<file_type>S)"
                  r"(:)(?P<element_number>\d{1,3})"
                  r"(/(?P<sub_element>\d{1,2}))?", tag, flags=re.IGNORECASE)
    if t:
        if t.group('sub_element') is not None:
            if (0 <= int(t.group('element_number')) <= 255) \
                    and (0 <= int(t.group('sub_element')) <= 15):
                return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                          'file_number': '2',
                                          'element_number': t.group('element_number'),
                                          'sub_element': t.group('sub_element'),
                                          'read_func': b'\xa2',
                                          'write_func': b'\xab',
                                          'address_field': 3}
        else:
            if 0 <= int(t.group('element_number')) <= 255:
                return True, t.group(0), {'file_type':  t.group('file_type').upper(),
                                          'file_number': '2',
                                          'element_number': t.group('element_number'),
                                          'read_func': b'\xa2',
                                          'write_func': b'\xab',
                                          'address_field': 2}

    t = re.search(r"(?P<file_type>B)(?P<file_number>\d{1,3})"
                  r"(/)(?P<element_number>\d{1,4})",
                  tag, flags=re.IGNORECASE)
    if t:
        if (1 <= int(t.group('file_number')) <= 255) \
                and (0 <= int(t.group('element_number')) <= 4095):
            bit_position = int(t.group('element_number'))
            element_number = bit_position / 16
            sub_element = bit_position - (element_number * 16)
            return True, t.group(0), {'file_type': t.group('file_type').upper(),
                                      'file_number': t.group('file_number'),
                                      'element_number': element_number,
                                      'sub_element': sub_element,
                                      'read_func': b'\xa2',
                                      'write_func': b'\xab',
                                      'address_field': 3}

    return False, tag