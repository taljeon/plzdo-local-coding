"""Provider-neutral strict JSON bytes shared by runtime and staged checkers."""
import json
import math


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key: ' + key)
        value[key] = item
    return value


def _finite_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Nonfinite JSON number')
    return number


def strict_json(text):
    def invalid_constant(value):
        raise ValueError('Non-JSON constant: ' + value)
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=invalid_constant, parse_float=_finite_number)


def canonical_bytes(value):
    def validate(item):
        if isinstance(item, dict):
            if not all(type(key) is str for key in item):
                raise ValueError('JSON object keys must be strings')
            for child in item.values():
                validate(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                validate(child)
        elif item is not None and type(item) not in (bool, int, float, str):
            raise ValueError('Expected JSON-safe values')
    validate(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')
