#802.11 HT (N) PLCP

## See especially equations 20-91 through 20-94, in \s 20.4.3
## And tables 20-29 through 30-44? in \s 20.6 (Parameters for HT MCSs)

## PLCP sequences -- see \s 20.3
## Non-HT:
## L-STF (8 us),
## L-LTF (8 us),
## L-SIG (4 us)
## = 20 us

## HT-Mixed:
## L-STF,
## L-LTF,
## L-SIG,
## HT-SIG (8 us),
## HT-STF (4 us),
## Data HT-DLTFs (4 us per LTF) (may be 1, 2 or 4),
## Extension HT-ELTFs (4 us per LTF) (may be 0, 1, 2 or 4),
## = 32 us + data & extension LTFs

## HT-Greenfield:
## GT-GF-STF (8 us),
## HT-LTF1 (8 us),
## HT-SIG (8 us),
## Data HT-DLTFs (4 us per LTF) (may be 1, 2 or 4),
## Extension HT-ELTFs (4 us per LTF) (may be 0, 1, 2 or 4),
## = 24 us + data & extension LTFs


## See \s 20.3
## Microseconds
T = {
    'L-STF'         : 8.0,
    'L-LTF'         : 8.0,
    'L-SIG'         : 4.0,
    'HT-SIG'        : 8.0,
    'HT-STF'        : 4.0,
    'HT-DLTF'       : 4.0,
    'HT-ELTF'       : 4.0,
    'HT-GF-STF'     : 8.0,
    'HT-MIXED-LTF1' : 4.0,              # HT-LTF1, mixed
    'HT-GF-LTF1'    : 8.0,              # HT-LTF1, greenfield
    'HT-LTFs'       : 4.0,
    'SYM'           : 4.0,              # T_SYM, Table 20-6
    'SYMS'          : 3.6,              # T_SYMS, Table 20-6
    }
