class AP:
   def __init__(self, channel, src_addr, dst_addr, dst_click_addr, dst_ether):
      self.ch = channel
      self.sip = src_addr
      self.dip = dst_addr
      self.dcip = dst_click_addr
      self.dether = dst_ether

   
   def __repr__(self):
      return "AP(channel=%d, src_addr=%s, dst_addr=%s, dst_click_addr=%s, dst_ether=%s)" % (self.ch, self.sip, self.dip, self.dcip, self.dether)
   
   def __getitem__(self, idx):
      if idx == 0:
         return self.ch
      elif idx == 1:
         return self.sip
      elif idx == 2:
         return self.dip
      elif idx == 3:
         return self.dcip
      elif idx == 4:
         return self.dether

   def __setitem__(self, idx, val):
      if idx == 0:
          self.ch = val
      elif idx == 1:
          self.sip = val
      elif idx == 2:
          self.dip = val
      elif idx == 3:
          self.dcip = val
      elif idx == 4:
          self.dether = val
   
   def __len__(self):
      return 5
