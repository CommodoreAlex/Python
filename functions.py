#Default Arguments
#Syntax for a function
#def functionname( parameters ):
    #"function_docstring"
    #function_suite
    #return [expression]
    
#def printme( str ):
    #"This prints a passed string into this function"
    #print str;
    #return;
    
#Now I'm able to call printme function
#printme("I'm first to call to user defined function!");
#printme("Again second call to the same fucntion");
#Now the function is called through 'printme'

#def changeme( mylist ):
    #"This changes a passed list into this function"
    #mylist.append([1,2,3,4]);
    #print "Values inside the function: ", mylist;
    #return;

#mylist = [10, 20, 30];
#changeme( mylist );
#print "Values outisde the function: ", mylist

#def printinfo( name, age = 35):
    #"This prints a passed info into this function"
    #print "Name: ", name;
    #print "Age: ", age;
    #return;
    
#Now you can call printinfo function
#printinfo(age = 15, name = "Alex" );
#printinfo(name = "Connor" );
#----------------------------
#Variable Length Arguments

#Syntax
#def functionname([formal_args,] *var_args_tuple ):
    #"function_docstring;
    #function_suite;
    #return [expression];

#Function definition is here
#def printinfo( arg1, *vartuple ):
    #"This prints a variable passed arguments"
    #print "Output is: "
    #print arg1;
    #for var in vartuple:
        #print var;
    #return;

# Now the function is enabled
#printinfo( 10 );
#printinfo( 70, 60, 50 );

#---------------------------
#Lambda functions
#Syntax
#lambda [arg1 [,arg2.....argn]]:expression

#sum = lambda arg1, arg2: arg1 + arg2; #This is adding the two values below using the sum function created

#print "Value of total :", sum(10, 20)
#print "Value of total: ", sum(20, 20)

#Returning a value from a function
#def sum( arg1, arg2 ):
    #Add both parameters and return them."
    #total = arg1 + arg2
    #print "Inside the function : ", total
    #return total;
    
#Now the sum function is callable
#total = sum( 10, 20 );
#print "Outside the function : ", total
#-----------------------------
#Global vs. Local variables
total = 0 #This is a global variable
#def sum( arg1, arg2 ):
    #Add both of the parameters and return them."
    #total = arg1 + arg2; #Here total is local variable
    #print "Inside the function local total : ", total
    #return total;

#Now you can call sum function
#sum( 10, 20 );
#print "Outside the function global total : ", total
