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

import hashlib
import shutil
import sys
from importlib import resources
from pathlib import Path

from tuf.ngclient import Updater

TUF_DIR = Path.home() / ".sigstore" / "root"
METADATA_DIR = TUF_DIR / "metadata"
TARGETS_DIR = TUF_DIR / "targets"
EXPECTED_ROOT_DIGEST = (
    "8e34a5c236300b92d0833b205f814d4d7206707fc870d3ff6dcf49f10e56ca0a"
)
REPO_URL = "https://storage.googleapis.com/sigstore-tuf-root/"
# TODO: might it make sense to break these out by requirement
# (signing vs. verifying)?
SIGSTORE_TARGETS = [
    "ctfe.pub",
    "ctfe.staging.pub",
    "fulcio_intermediate.crt.pem",
    "fulcio_intermediate.crt.staging.pem",
    "fulcio.crt.pem",
    "fulcio.crt.staging.pem",
    "rekor.pub",
    "rekor.staging.pub",
]


class TrustUpdater:
    # Updater.__init__() does the paving, by calling a separate function (below)
    #   TUF_DIR -> Path: cache_dir
    #   REPO_URL -> Optional[str]: repo_url – default is public good url
    #   EXPECTED_ROOT_DIGEST -> Optional[str]: bootstrap_root_digest – default
    def __init__(self) -> None:
        # TODO: parameterise and add params to __init__
        self.prepare_local_cache()

    # Updater.prepare_local_cache() will create and populate the local directories
    def prepare_local_cache(self) -> None:
        """ """
        tuf_root = METADATA_DIR / "root.json"
        if not tuf_root.exists():
            TUF_DIR.mkdir(mode=0o0700, parents=True, exist_ok=True)
            METADATA_DIR.mkdir(mode=0o0700, parents=True, exist_ok=True)
            TARGETS_DIR.mkdir(mode=0o0700, parents=True, exist_ok=True)

            # Ensure the bundled copy of the root json is not tampered with
            # NOTE: this check requires us to update EXPECTED_ROOT_DIGEST each time
            # we bundle a newer root.json
            bootstrap_root = resources.read_binary("sigstore._store", "root.json")
            bootstrap_root_digest = hashlib.sha256(bootstrap_root).hexdigest()
            if not bootstrap_root_digest == EXPECTED_ROOT_DIGEST:
                print(
                    "Trusted root metadata does not match expected file digest!",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Copy the trusted root and existing targets from the store
            with resources.path("sigstore._store", "root.json") as res:
                shutil.copy2(res, METADATA_DIR)
            for target in SIGSTORE_TARGETS:
                with resources.path("sigstore._store", target) as res:
                    shutil.copy2(res, TARGETS_DIR)

    # Updater.check_local_cache() will ensure the metadata directory is sane
    def check_local_cache(self) -> None:
        """ """
        # TODO: how?
        pass

    # Updater.update() retrieves new metadata (and all targets? or fetch by usage?)
    def update(self) -> None:
        """ """
        updater = Updater(
            metadata_dir=str(METADATA_DIR),
            metadata_base_url=f"{REPO_URL}",
            target_base_url=f"{REPO_URL}/targets/",
            target_dir=str(TARGETS_DIR),
        )
        # TODO: Check whether we should update based on settings and expiration of root
        # Fetch the latest version of all of the Sigstore certificates
        updater.refresh()

        for target in SIGSTORE_TARGETS:
            target_info = updater.get_targetinfo(target)
            if not target_info:
                print(f"Failed to find update information about {target}", sys.stderr)
                sys.exit(1)
            cached_target = updater.find_cached_target(target_info)
            if not cached_target:
                updater.download_target(target_info)
