# Prerequisite: brew install imagemagick

base_dir=$(dirname "$0")/../../
source="$base_dir"/electrumsv/data/icons/electrum-sv.svg

mkdir ElectrumSV.iconset
convert -background None -resize 16x16 $source ElectrumSV.iconset/icon_16x16.png
convert -background None -resize 32x32 $source ElectrumSV.iconset/icon_32x32.png
cp ElectrumSV.iconset/icon_32x32.png ElectrumSV.iconset/icon_16x16@2x.png
convert -background None -resize 64x64 $source ElectrumSV.iconset/icon_64x64.png
cp ElectrumSV.iconset/icon_64x64.png ElectrumSV.iconset/icon_32x32@2x.png
convert -background None -resize 128x128 $source ElectrumSV.iconset/icon_128x128.png
cp ElectrumSV.iconset/icon_128x128.png ElectrumSV.iconset/icon_64x64@2x.png
convert -background None -resize 256x256 $source ElectrumSV.iconset/icon_256x256.png
cp ElectrumSV.iconset/icon_256x256.png ElectrumSV.iconset/icon_128x128@2x.png
convert -background None -resize 512x512 $source ElectrumSV.iconset/icon_512x512.png
cp ElectrumSV.iconset/icon_512x512.png ElectrumSV.iconset/icon_256x256@2x.png
convert -background None -resize 1024x1024 $source ElectrumSV.iconset/icon_512x512@2x.png
iconutil -c icns ElectrumSV.iconset -o "$base_dir"/contrib/osx/ElectrumSV.icns
rm -r ElectrumSV.iconset
