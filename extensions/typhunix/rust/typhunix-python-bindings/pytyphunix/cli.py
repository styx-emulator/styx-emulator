# BSD 2-Clause License
#
# Copyright (c) 2024, Styx Emulator Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import json
import sys
import argparse
from packaging.version import Version
from pytyphunix import TyphunixServer


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "cli tool for interacting with a typhunix server. \n\n"
            "Note: Set/export TYPHUNIX_URL=http://server:port"
        )
    )
    parser.add_argument(
        "-s", "--symbols", action="store_true", help="Retrieve symbols"
    )
    parser.add_argument(
        "-d", "--data-types", action="store_true", help="Retrieve data types"
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=("json", "jsonl", "repr"),
        default="jsonl",
        help="output format",
    )
    parser.add_argument(
        "--typhunix-version",
        type=str,
        default="1.0.0",
        help="""Output version. ("< 1.0.0" for DragonState)""",
    )

    parser.add_argument(
        "--include-new-fields",
        action="store_true",
        help="When version is < 1.0.0, include new fields",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    ty_version: Version = Version(args.typhunix_version)
    exclude_new = not args.include_new_fields
    if not TyphunixServer.is_running():
        print("Server not running", file=sys.stderr)
        sys.exit(1)
    prog_ids = TyphunixServer.pids()
    if not prog_ids:
        print("Server running, but has no data", file=sys.stderr)
        sys.exit(1)

    try:
        for pid in prog_ids:
            server = TyphunixServer(pid.name, pid.source_id)
            if not args.symbols and not args.data_types:
                if args.format == "repr":
                    print(f"{pid}")
                else:
                    print(
                        json.dumps(
                            dict(name=pid.name, source_id=pid.source_id)
                        )
                    )

            if args.symbols:
                if args.format == "repr":
                    for s in server.symbols():
                        print(f"{s}")
                else:
                    syms = server.symbols_dict(
                        version=ty_version,
                        exclude_new_fields=exclude_new,
                    )
                    if args.format == "jsonl":
                        for s in syms:
                            print(json.dumps(s))
                    else:
                        print(json.dumps(syms))
            if args.data_types:
                if args.format == "repr":
                    for d in server.data_types():
                        print(f"{d}")
                else:
                    dts = server.data_types_dict(
                        version=ty_version,
                        exclude_new_fields=exclude_new,
                    )
                    if args.format == "jsonl":
                        for d in dts:
                            print(json.dumps(d))
                    else:
                        print(json.dumps(dts))

    except BrokenPipeError:
        pass
    except Exception as ex:
        print(f"{ex}", file=sys.stderr)
