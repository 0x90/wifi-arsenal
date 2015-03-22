#!/usr/bin/env python
# encoding: utf-8
"""
Convert Chinese character to pinyin.
"""
class Pinyin():
    def __init__(self, data_path='/home/alexy/wpp/wpp/util/Mandarin.dat'):
        self.dict = {}
        for line in open(data_path):
            k, v = line.split('\t')
            self.dict[k] = v
        self.splitter = '' 

    def get_pinyin(self, chars=u"你好吗"):
        result = []
        for char in chars:
            key = "%X" % ord(char)
            print key
            try:
                result.append(self.dict[key].split(" ")[0].strip()[:-1].lower())
            except:
                result.append(char)
        return self.splitter.join(result)

    def get_initials(self, char=u'你'):
        try:
            return self.dict["%X" % ord(char)].split(" ")[0][0]
        except:
            return char


if __name__ == "__main__":
    p = Pinyin()
    py = p.get_pinyin(u"西安")
    py = '%s%s' % (py[0].upper(), py[1:])
    print py
    #p.get_initials(u"北")
