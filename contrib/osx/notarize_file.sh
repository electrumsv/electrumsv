#!/usr/bin/env bash
# This file is sourced from Electrum Core via Metabrainz Picard.
#   https://github.com/metabrainz/picard/blob/e1354632d2db305b7a7624282701d34d73afa225/scripts/package/macos-notarize-app.sh
# You can find this license at this URL: https://choosealicense.com/licenses/gpl-2.0/
#
# NOTE(rt12) The license used for Picard at the given revision is GPLv2.

if [ -z "$1" ]; then
    echo "Specify file as first parameter"
    exit 1
fi

if [ -z "$APPLE_ID_USER" ] || [ -z "$APPLE_ID_PASSWORD" ] || [ -z "$APPLE_ID_PROVIDER" ]; then
    echo "You need to set your Apple ID credentials with \$APPLE_ID_USER, \$APPLE_ID_PASSWORD and \$APPLE_ID_PROVIDER."
    exit 1
fi

NOTARISATION_FILE=$(basename "$1")
NOTARISATION_FILE_DIR=$(dirname "$1")

cd "$NOTARISATION_FILE_DIR" || exit 1

# Submit for notarization
echo "Submitting $NOTARISATION_FILE for notarization..."
RESULT=$(xcrun altool --notarize-app --type osx \
  --file "${NOTARISATION_FILE}" \
  --primary-bundle-id io.electrumsv.electrumsv \
  --username $APPLE_ID_USER \
  --password @env:APPLE_ID_PASSWORD \
  --asc-provider $APPLE_ID_PROVIDER \
  --output-format xml)

if [ $? -ne 0 ]; then
  echo "Submitting $NOTARISATION_FILE failed:"
  echo "$RESULT"
  exit 1
fi

REQUEST_UUID=$(echo "$RESULT" | xpath -e \
  "//key[normalize-space(text()) = 'RequestUUID']/following-sibling::string[1]/text()")

if [ -z "$REQUEST_UUID" ]; then
  echo "Submitting $NOTARISATION_FILE failed:"
  echo "$RESULT"
  exit 1
fi

echo "$(echo "$RESULT" | xpath -e \
  "//key[normalize-space(text()) = 'success-message']/following-sibling::string[1]/text()" 2> /dev/null)"

# Poll for notarization status
echo "Submitted notarization request $REQUEST_UUID, waiting for response..."
sleep 60
while :
do
  RESULT=$(xcrun altool --notarization-info "$REQUEST_UUID" \
    --username "$APPLE_ID_USER" \
    --password @env:APPLE_ID_PASSWORD \
    --asc-provider $APPLE_ID_PROVIDER \
    --output-format xml)
  STATUS=$(echo "$RESULT" | xpath -e \
    "//key[normalize-space(text()) = 'Status']/following-sibling::string[1]/text()" 2> /dev/null)

  if [ "$STATUS" = "success" ]; then
    echo "Notarization of $NOTARISATION_FILE succeeded!"
    break
  elif [ "$STATUS" = "in progress" ]; then
    echo "Notarization in progress..."
    sleep 20
  else
    echo "Notarization of $NOTARISATION_FILE failed:"
    echo "$RESULT"
    exit 1
  fi
done

# Staple the notary ticket
xcrun stapler staple "$NOTARISATION_FILE"
