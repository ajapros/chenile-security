new_version=$(cat chenile-security-version.txt)
git add .
git commit -m "${new_version}"
git push origin main
make tag tag=$new_version
make push-tags

