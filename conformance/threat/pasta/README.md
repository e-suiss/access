# PASTA flows

One file per high-impact flow walks the seven PASTA stages: objectives, technical scope,
decomposition, threats, vulnerabilities, attacks and risk. Each flow names its attack tree, and
each leaf of a tree is bound to a threat-model row and to a test or a declared limit.
`cargo xtask check` (`threat-model`) checks the files here.
