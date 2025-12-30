#!/usr/bin/env python3
import argparse
import sys
import time

parser = argparse.ArgumentParser(description='Serial monitor')
parser.add_argument('--device', default='/dev/ttyUSB0', help='Serial device path')
args = parser.parse_args()

try:
    with open(args.device, 'rb', buffering=0) as ser:
        print(f'Serial monitor started on {args.device}. Press Ctrl+C to exit.')
        print('=' * 60)
        sys.stdout.flush()

        while True:
            try:
                data = ser.read(1)
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            except KeyboardInterrupt:
                break
            except OSError as e:
                print(f'\nError: {e}')
                time.sleep(0.1)
except FileNotFoundError:
    print(f'Serial device not found: {args.device}')
    sys.exit(1)
except PermissionError:
    print(f'Permission denied: {args.device}')
    sys.exit(1)
except OSError as e:
    print(f'Failed to open serial port: {e}')
    sys.exit(1)
