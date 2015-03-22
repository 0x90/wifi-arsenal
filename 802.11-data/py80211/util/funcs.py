import math 
from ..constants.plcp_times import T
from ..constants.mcs_indices import tables, HT_AGGREGATE_TABLE

import mcs_table
import xxx_defaults


def __init__():
    pass


def N_STS_from_N_SS(N_SS, STBC):
    """ Number of space-time streams (N_{STS}) from number of spatial
    streams (N_{SS}), and the space-time block coding (STBC) used.

    The standard gives this a table (20-12), but it's just addition!
    """

    return N_SS + STBC

def N_HTDLTF_from_N_STS(N_STS):
    """Number of HT Data LTFs from number of space-time streams"""
    
    table_20_13 = {1 : 1,
                   2:  2,
                   3:  4,
                   4:  4}

    return table_20_13[N_STS]

def N_HTELTF_from_N_ESS(N_ESS):
    """Number of HT Extension LTFs from number of extension spatial streams"""

    table_20_14 = {0: 0,
                   1: 1,
                   2: 2,
                   3: 4}

    return table_20_14[N_ESS]

def N_SYM_BCC(length, STBC_p, N_ES, N_DBPS):
    """
    Number of symbols for data.

    Equation 20-32 & discussion.

    Args:
        length: # of data bits,
        N_DBPS: # of data bits per OFDM symbol
        N_ES = Number of BCC encoders

    Returns:
        Number of symbols used
    """


    m_STBC = {True: 2,
              False: 1}[STBC_p]

    n_sym = m_STBC * math.ceil((8*length + 16 + 6*N_ES)/(m_STBC * N_DBPS))

    return n_sym

def N_SYM_LDPC(length):
    
    """The equations for LDPC are complicated, and I don't think they
    buy us anything important right now."""
    
    raise NotImplementedError()

## See \s 20.4.3

## Non-HT preamble
T_LEG_PREAMBLE = T['L-STF'] + T['L-LTF']

## HT-mixed preable
def T_HT_PREAMBLE(N_LTF):
    T_HT_LTF1 = T['HT-MIXED-LTF1']
    
    return (T['HT-STF'] +
            T_HT_LTF1 + 
            (N_LTF-1)*T['HT-LTFs'])

## HT-greenfield preable
def T_GF_HT_PREAMBLE(N_LTF):
    T_HT_LTF1 = T['HT-GF-LTF1']

    return (T['HT-GF-STF'] +
            T_HT_LTF1 + 
            (N_LTF-1)*T['HT-LTFs'])


def HT_TXTIME(mode, short_gi_p, chan_width, MCS_idx, length ):
    """
    TXTIME calculation from \S 20.4.3

    Args:
        mode       : 'greenfield' or 'mixed'
        short_gi_p : True for 400ns guard interval, False for 800ns (standard)
        chan_width : Channel width in MHz
        MCS_idx    : MCS Index
        length     : Length of the PSDU (roughly 'data') in bits

    Returns:
        Duration of transmit time in microseconds

    Raises:
        ValueError, KeyError, NotImplementedError
    """

    phy_parms = HT_AGGREGATE_TABLE.get_params(chan_width=chan_width,
                                              mcs_index=MCS_idx,
                                              phy='HT')

    N_SS = int(phy_parms['N_SS'])
    N_ES = int(phy_parms['N_ES'])
    N_DBPS = int(phy_parms['NDBPS'])
    STBC   = xxx_defaults.STBC
    N_ESS  = xxx_defaults.N_ESS
        
    ## How many LTFs?  See eq. 20-22
    N_STS = N_STS_from_N_SS(N_SS, STBC)
    N_DLTF = N_HTDLTF_from_N_STS(N_STS)
    N_ELTF = N_HTELTF_from_N_ESS(N_ESS)
    N_LTF = N_DLTF + N_ELTF
    if N_LTF > 5:
        raise ValueError("At most 5 LTFs are allowed.  See \s 20.3.9.4.6", N_LTF)
    
    try:
        func = {'mixed'     :HT_TXTIME_MIXED,
                'greenfield':HT_TXTIME_GREENFIELD}[mode]
        return func(short_gi_p, N_LTF, N_ES, N_DBPS, length)
    
    except KeyError, e:
        raise KeyError('Unknown HT mode {}'.format(mode), e)

def HT_TXTIME_MIXED(short_gi_p, N_LTF, N_ES, N_DBPS, length):
    """ Equations 20-91 & 20-92"""

    ### Common portion of 20-91 and 20-92
    SignalExtension = xxx_defaults.SignalExtension
    t_shared = (T_LEG_PREAMBLE +
                T['L-SIG'] +
                T_HT_PREAMBLE(N_LTF) +
                T['HT-SIG'] +
                SignalExtension)
    
    BCC_p  = xxx_defaults.BCC_p
    STBC_p = xxx_defaults.STBC_p
    

    if BCC_p:
        N_SYM = N_SYM_BCC(length, STBC_p, N_ES, N_DBPS)
    else:
        ### XXX will need other parameters
        N_SYM = N_SYM_LDPC(length)


    if short_gi_p:
        # Equation 20-91: Short (400 ns) GI
        t_data = T['SYM'] * math.ceil((T['SYMS']*N_SYM)/(T['SYM']))
    else:
        # Equation 20-92: Standard/Long (800 ns) GI
        t_data = T['SYM'] * N_SYM

    return t_shared + t_data


def get_PHY_params():
    pass

def HT_TXTIME_GREENFIELD(short_gi_p, length):
    raise NotImplementedError()



def _main(args):
    import pprint
    """ Test routine.  Do not use for anything!"""
    print HT_TXTIME('mixed',False,20,0,40)

    #print pprint.pprint(tables)
    foo = mcs_table.combine_tables(tables)
    bar = mcs_table.WrappedTable(foo)        
    # print bar
    # print bar.get_params(chan_width=20,mcs_index=2)
    # print type(bar.get_params(chan_width=20,mcs_index=2,p_list=['Mod. Stream 1', 'DR 800 ns']))
    # print "'" + str(bar.get_params(chan_width=20,mcs_index=2)['Mod. Stream 1']) + "'"

if __name__ == '__main__':
    import sys
    sys.exit(_main(sys.argv))
