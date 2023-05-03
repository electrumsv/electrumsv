#!/usr/bin/env bash
# This file is sourced from Electrum Core via Metabrainz Picard.
#   https://github.com/metabrainz/picard/blob/e1354632d2db305b7a7624282701d34d73afa225/scripts/package/macos-notarize-app.sh
# NOTE(rt12) The license used for Picard at the given revision is GPLv2. No ElectrumSV licensing
#   applies to this file.
# You can find this license at this URL: https://choosealicense.com/licenses/gpl-2.0/

if [ -z "$1" ]; then
    echo "Specify app bundle as first parameter"
    exit 1
fi

if [ -z "$APPLE_ID_USER" ] || [ -z "$APPLE_ID_PASSWORD" ] || [ -z "$APPLE_ID_PROVIDER" ]; then
    echo "You need to set your Apple ID credentials with \$APPLE_ID_USER, \$APPLE_ID_PASSWORD and \$APPLE_ID_PROVIDER."
    exit 1
fi

NOTARISATION_FILE=$(basename "$1")
NOTARISATION_FILE_DIR=$(dirname "$1")

cd "$NOTARISATION_FILE_DIR" || exit 1

# Package app for submission
echo "Generating ZIP archive ${NOTARISATION_FILE}.zip..."
ditto -c -k --rsrc --keepParent "$NOTARISATION_FILE" "${NOTARISATION_FILE}.zip"

# Submit for notarization
echo "Submitting $NOTARISATION_FILE for notarization..."
xcrun notarytool submit \
  --username $APPLE_ID_USER \
  --password @env:APPLE_ID_PASSWORD \
  --team-id $APPLE_ID_PROVIDER
  "${NOTARISATION_FILE}.zip" \
  --wait

if [ $? -ne 0 ]; then
  echo "Submitting $NOTARISATION_FILE failed:"
  exit 1
fi

# Staple the notary ticket
xcrun stapler staple "$NOTARISATION_FILE"

# rm zip
rm "${NOTARISATION_FILE}.zip"
