import pandas as pd
import StringIO

class MCS_Table(object):

    MAX_SS = 4                          # Maximum spatial streams

    def __init__(self, text, phy_type, chan_width, N_SS, N_ES, EQM):
        """
        Standard initializer:
        
        From textual representation of table, and supplied ancillary information.        
        """
        self.phy_type = phy_type
        self.chan_width_MHz = chan_width
        self.N_SS = N_SS
        self.N_ES = N_ES
        self.EQM = EQM
        self.text = text
        self.tab = self._panda()

    # def __init__(self, full_table):
    #     """
    #     Wrap existing _panda-generated table.        
    #     """

    #     self.tab = full_table
    #     self.phy_type = None
    #     self.chan_width_MHz = None
    #     self.N_SS = None
    #     self.EQM = None
    #     self.text = 'N/A'

    def __str__(self):
        return "{} PHY, {} MHz, {} SS, {} ES, EQM={}".format(
            self.phy_type,
            self.chan_width_MHz,
            self.N_SS,
            self.N_ES,
            self.EQM) + "\n" + str(self.tab)

    def __repr__(self):
        return str(self)

    def _panda(self):
        tab = pd.io.parsers.read_table(StringIO.StringIO(self.text))

        # Sanity checks
        ## Expect mod stream columns for each SS in UEQM
        if not self.EQM:
            for i_ss in range(self.N_SS):
                expected_col_name = "Mod. Stream {}".format(i_ss+1)
                if not expected_col_name in tab.columns:
                    raise ValueError("Table has UEQM, but no column '{}'".format(expected_col_name))
        else:
        ## Expect single modulation column if EQM
            if not "Mod." in tab.columns:
                raise ValueError("Table has EQM, but no column 'Mod.'")

        ## Expect N_ES if not specified for whole table
        if self.N_ES is None:
            if not "N_ES" in tab.columns:
                raise ValueError("Table has no defined N_ES, and no N_ES column")
        ## "Extend" with object-supplied attributes
        for (attr, name) in [(self.phy_type, 'PHY'),
                             (self.chan_width_MHz, 'Chan MHz'),
                             (self.N_SS, 'N_SS'),
                             (self.N_ES, 'N_ES')]:
            if attr is not None:
                tab[name]=attr

        ## Set per-stream modulation data, always
        for i_ss in range(1, MCS_Table.MAX_SS+1):
            expected_col_name = "Mod. Stream {}".format(i_ss)
            if i_ss <= self.N_SS:
                if self.EQM:
                    # This should exist, and we have to supply it
                    assert (expected_col_name not in tab.columns)
                    tab[expected_col_name] = tab['Mod.']
                else:
                    # This should exists, and it should already be there
                    assert (expected_col_name in tab.columns)
            else:
                # This should not exist, but we'll put an explicit NA in for it
                tab[expected_col_name] = float('NaN')
                    
        return tab

    def as_DataFrame(self):
        return self.tab

def combine_tables (tables):
    dfs = [t.as_DataFrame() for t in tables]
    return pd.concat(dfs, ignore_index=True)


class WrappedTable (object):

    def __init__(self, panda_tab):
        self.tab = panda_tab

    def get_params(self, chan_width, mcs_index, phy='HT', p_list=None):
        result= self.tab.ix[(self.tab['Chan MHz'] == chan_width) &
                            (self.tab['MCS Index'] == mcs_index) &
                            (self.tab['PHY']==phy)]
        (nrow, ncol) = result.shape
        if nrow < 1:
            raise KeyError("No results for PHY={}, Chan MHz={}, MCS Index={}".format(phy, chan_width, mcs_index))
        if nrow > 1:
            msg="Non-unique results for PHY={}, Chan MHz={}, MCS Index={}".format(phy, chan_width, mcs_index)
            raise ValueError(msg, result)
        if p_list is None:
            return result
        else:
            return result.ix[:,p_list]
    
    

