class test(object):

    def __init__(self,name,city):
        self.name=name
        self.city=city

    def __eq__(self,other):
        hash_equality= (self.name==other.name)
        if(not hash_equality):
            #check with lower
            return (self.name.lower()==other.name.lower())


    def  __hash__(self):
        return self.name.__hash__()

my_dict={}
a=test("a","city1")
my_dict[a]="obj1"
b=test("a","city2")
print b in my_dict  #prints true
c=test("A","city1")
print c in my_dict  #prints false
print c in my_dict.keys() #prints true
