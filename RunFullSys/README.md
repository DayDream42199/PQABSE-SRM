# RunFullSys

`RunFullSys` is now the AWS deployment tree for the split system roles:

- `TA+IA+Blockchain`
- `Edge node`
- `CS`
- `MDO`
- `MDU`

This directory is no longer meant to be the local demo harness. Local experimentation stays in `RunLocal`.

What remains here:

- the per-role runtime scripts you will run on the real machines
- the per-role self-contained application copies in each `<role>/app`
- AWS/Nitro deployment instructions

Start with:

- [AWS_DEPLOYMENT.md](/home/chees/FinalProjAllBuild/RunFullSys/AWS_DEPLOYMENT.md)
- [TA+IA+Blockchain README](</home/chees/FinalProjAllBuild/RunFullSys/TA+IA+Blockchain/README.md>)
- [Edge node README](</home/chees/FinalProjAllBuild/RunFullSys/Edge node/README.md>)
- [CS README](/home/chees/FinalProjAllBuild/RunFullSys/CS/README.md)
- [MDO README](/home/chees/FinalProjAllBuild/RunFullSys/MDO/README.md)
- [MDU README](/home/chees/FinalProjAllBuild/RunFullSys/MDU/README.md)
