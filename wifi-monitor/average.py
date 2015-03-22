class WeightedAverage(object):
    """docstring for WeightedAverage"""
    def __init__(self, maxlen, default):
        super(WeightedAverage, self).__init__()
        self.max = maxlen
        self.values = []
        self.emavalues = []
        
        for i in range(0, maxlen):
            self.values.append(default)

    def push(self, new):
        """docstring for push"""
        # add newest item
        self.values.append(new)
        while len(self.values) > self.max:
            # remove oldest item
            self.values.pop(0)

    def emapush(self, new):
        """docstring for emapush"""
        # add newest item
        self.emavalues.append(new)
        while len(self.emavalues) > 2:
            # remove oldest item
            self.emavalues.pop(0)

    def emavalue(self, smooth):
        """docstring for emavalue"""
        #l = len(self.values)

        if self.emavalues == []:
            self.emapush(self.values[-2])
            self.emapush(self.values[-1])

            return self.values[-1]

        else:
            #print "self.emavalues", self.emavalues
            #print "self.values", self.values

            #print self.emavalues[1], self.values[l-1]
            
            sn = smooth * self.emavalues[-1] + (1 - smooth) * self.values[-1]
            self.emapush(sn)
            
        return sn

    def value(self):
        """docstring for value"""
        i = self.max
        denominator = 0.0
        numerator = 0.0

        if self.values == []:
            #print "in average.py: self.values is []"
            return 10 # SHOULD be same as MAX_METRIC in apselect.py

        for v in reversed(self.values):
            numerator += i * i * v
            denominator += i * i
            i -= 1

        return float(numerator)/denominator

    def __str__(self):
        return "%f" % self.value()
    
    def __repr__(self):
        return "%f" % self.value()
    
class Average(object):
    """docstring for Average"""
    def __init__(self, maxlen):
        super(Average, self).__init__()
        self.max = maxlen
        self.values = []
    
    def push(self, new):
        """docstring for push"""
        # add newest item
        self.values.append(new)
        if len(self.values) > max:
            # remove oldest item
            self.values.pop(0)

    def value(self):
        """docstring for value"""
        return reduce(lambda x, y: x+y, self.values, 0) / len(self.values)

def main():
    """docstring for main"""
    a = WeightedAverage(3)
    a.push(10.0)
    print a.emavalue(0.2)
    a.push(20.0)
    print a.emavalue(0.2)
    a.push(30.0)
    print a.emavalue(0.2)
    a.push(40.0)
    print a.emavalue(0.2)
    a.push(50.0)
    print a.emavalue(0.2)

if __name__ == '__main__':
    main()
