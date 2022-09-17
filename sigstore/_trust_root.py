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
from typing import Optional

from tuf.api.metadata import Metadata, Timestamp
from tuf.ngclient import Updater

PUBLIC_GOOD_URL = "https://storage.googleapis.com/sigstore-tuf-root/"
EXPECTED_ROOT_DIGEST = (  # corresponds to public good 4.root.json
    "8e34a5c236300b92d0833b205f814d4d7206707fc870d3ff6dcf49f10e56ca0a"
)
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


# TODO: tests!
# * _prepare_local_cache() against a simple adversary
# * _should_update() against a simple adversary – what if
# * update() results in new files (i.e. local copies of TUF metadata)
class TrustUpdater:
    def __init__(self, tuf_dir: Optional[str] = None) -> None:
        if tuf_dir:
            _tuf_dir = Path(tuf_dir)
        else:
            _tuf_dir = Path.home() / ".sigstore" / "root"
        # TODO: this should be a param in order to support private and staging
        # instances of Sigstore
        self._repo_url = PUBLIC_GOOD_URL
        self._prepare_local_cache(_tuf_dir)

    def _prepare_local_cache(self, tuf_dir: Path) -> None:
        """
        Create and populate the local directories used by the TUF client
        """
        self._metadata_dir = tuf_dir / "metadata"
        self._targets_dir = tuf_dir / "targets"
        tuf_root = self._metadata_dir / "root.json"
        if not tuf_root.exists():
            tuf_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)
            self._metadata_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)
            self._targets_dir.mkdir(mode=0o0700, parents=True, exist_ok=True)

            # Ensure the bundled copy of the root json is not tampered with
            # NOTE: this check requires us to update EXPECTED_ROOT_DIGEST each
            # time we bundle a newer root.json
            bootstrap_root = resources.read_binary("sigstore._store", "root.json")
            bootstrap_root_digest = hashlib.sha256(bootstrap_root).hexdigest()
            if not bootstrap_root_digest == EXPECTED_ROOT_DIGEST:
                print(
                    "Trusted root metadata does not match expected file digest!",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Copy the trusted root and existing targets from the store
            # TODO: we need to be able to take a root.json that wasn't bundled
            #  with the implementation, i.e. for private sigstore deployments
            # (this also affects the bootstrap_root digest comparison above)
            with resources.path("sigstore._store", "root.json") as res:
                shutil.copy2(res, self._metadata_dir)
            for target in SIGSTORE_TARGETS:
                with resources.path("sigstore._store", target) as res:
                    shutil.copy2(res, self._targets_dir)
            # TODO: ensure the directory has appropriate file permissions?

    def _should_update(self) -> bool:
        """
        Should we reach out over the network to update TUF metadata?
        """
        # if we don't already have a downloaded timestamp metadata, we need
        # to update
        timestamp_path = self._metadata_dir / "timestamp.json"
        if not timestamp_path.exists():
            return True
        # if timestamp metadata has expired, we need to update
        timestamp = Metadata[Timestamp].from_file(str(timestamp_path))
        if timestamp.signed.is_expired():
            return True

        return False

    def update(self) -> None:
        """
        Update the TUF metadata and fetch any updated targets
        """
        if not self._should_update():
            return

        updater = Updater(
            metadata_dir=str(self._metadata_dir),
            metadata_base_url=f"{self._repo_url}",
            target_base_url=f"{self._repo_url}/targets/",
            target_dir=str(self._targets_dir),
        )

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

    @classmethod
    def is_created(tuf_dir: Optional[str] = None) -> bool:
        """
        Has the TUF update cycle triggered by `update()` has been run at least
        once? If it has, we would expect the timestamp metadata to have been
        retrieved and stored in the cache.
        """
        if tuf_dir:
            _tuf_dir = Path(tuf_dir)
        else:
            _tuf_dir = Path.home() / ".sigstore" / "root"
        timestamp_path = _tuf_dir / "metadata" / "timestamp.json"
        return timestamp_path.exists()
