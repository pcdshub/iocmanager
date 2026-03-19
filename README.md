# IOC Manager

IOC manager is a GUI and CLI application for managing procServ instances that run EPICS IOCs.

## Deploying a Release

1. Pick the release to deploy and use that tag instead of R1.0.0 in the instructions below
```
export RELVER=R1.0.0
```
2. Make sure you have no conda environment sourced
3. Enter the release area
```
cd $PYPS_SITE_TOP/apps/iocmanager
```
4. Clone the release into the release area at the new version:
```
git clone git@github.com:pcdshub/iocmanager.git --depth 1 -b $RELVER $RELVER
```
5. Enter the repo and make
```
cd ${RELVER}
make
```
6. Test a little bit: make sure you can still run iocmanager and imgr
  - Note: this also will generate the .pyc files, which is helpful
```
./scripts/IocManager tst
./scripts/imgr --hutch tst list
```
7. Update the symbolic link "latest-R3" if we're in the R3 series, or "latest" if we're in the R2 series.
```
cd ..
ln -sfn $RELVER latest-R3
```
8. Write-protect the release
```
chmod -R a-w $RELVER
```
