# RunFullSys

`RunFullSys` is the networked deployment tree for the split system roles:

- `TA+IA+Blockchain`
- `Edge node`
- `CS`
- `MDO`
- `MDU`

Unlike the earlier version, this tree no longer expects a shared `service_bus` directory between machines. `TA+IA+Blockchain`, `Edge node`, and `CS` now run as HTTP services, while `MDO` and `MDU` act as HTTP clients.

The crypto, search, revocation, and ZKP logic still live inside each role's local `app/` copy and are executed through the same C++ binaries as before. The transport layer is what changed.

Start here:

- [AWS_DEPLOYMENT.md](/home/chees/FinalProjAllBuild/RunFullSys/AWS_DEPLOYMENT.md)
- [TA+IA+Blockchain README](</home/chees/FinalProjAllBuild/RunFullSys/TA+IA+Blockchain/README.md>)
- [Edge node README](</home/chees/FinalProjAllBuild/RunFullSys/Edge node/README.md>)
- [CS README](/home/chees/FinalProjAllBuild/RunFullSys/CS/README.md)
- [MDO README](/home/chees/FinalProjAllBuild/RunFullSys/MDO/README.md)
- [MDU README](/home/chees/FinalProjAllBuild/RunFullSys/MDU/README.md)
