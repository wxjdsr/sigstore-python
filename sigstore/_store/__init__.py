# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# NOTE: This is arguably incorrect, since _store only contains non-Python files.
# However, due to how `importlib.resources` is designed, only top-level resources
# inside of packages or modules can be accessed, so this directory needs to be a
# module in order for us to programmatically access the keys and root certs in it.
#
# Why do we bother with `importlib` at all? Because we might be installed as a
# ZIP file or an Egg, which in turn means that our resource files don't actually
# exist separately on disk. `importlib` is the only reliable way to access them.


# Index of files by source:
#
# https://storage.googleapis.com/tuf-root-staging
#   * ctfe.staging.pub
#   * fulcio.crt.staging.pem
#   * fulcio_intermediate.crt.staging.pem
#   * rekor.staging.pub
#
# https://storage.googleapis.com/sigstore-tuf-root
#   * ctfe.pub
#   * fulcio.crt.pem
#   * fulcio_intermediate.crt.pem
#   * rekor.pub

import shutil
from importlib import resources
from pathlib import Path
from typing import Optional

SIGSTORE_TARGETS = [
   "ctfe.pub",
   "ctfe.staging.pub",
   "fulcio_intermediate.crt.pem",
   "fulcio_intermediate.crt.staging.pem",
   "fulcio.crt.pem",
   "fulcio.crt.staging.pem",
   "rekor.pub",
   "rekor.staging.pub"
]


class Store:
    def __init__(self, trust_repo: Optional[str] = None) -> None:
        '''
        Initialize targets directory
        '''
        # Ensure the store directory exists
        if trust_repo is None:
            repo_dir = "targets"
        else:
            pass  # TODO: implement logic from the design for instances of
            # sigstore which are not the public good instances

        self._store_dir = Path.home() / ".sigstore" / "root"/ repo_dir
        self._store_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)

        for target in SIGSTORE_TARGETS:
            target_path = self._store_dir / target
            if target_path.exists():
                continue

            with resources.path("sigstore._store", target) as res:
                # TODO: what about file permissions here?
                shutil.copy2(res, target_path)

    @classmethod
    def _read_metadata(cls, metadata_name: str) -> bytes:
        '''
        read metadata (e.g. root.json) from metadata directory
        '''
        metadata_path = Path.home() / ".sigstore" / "root" / "metadata" / metadata_name
        metadata_bits = None
        with open(metadata_path, "rb") as metadata_file:
            metadata_bits = metadata_file.read()
        return metadata_bits

    @classmethod
    def _read_binary(cls, cert_name: str) -> bytes:
        '''
        read a file from targets directory into bytes
        '''
        # TODO: tests should overwrite HOME so we're not littering the user's
        cert_path = Path.home() / ".sigstore" / "root" / "targets" / cert_name
        cert_bits = None
        with open(cert_path, "rb") as cert_file:
            cert_bits = cert_file.read()
        return cert_bits

#FIXME: clearly wrong
# store = Store()
