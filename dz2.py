""" Attempt #1
Jezik za obradu mikoloških uzoraka i njihovu klasifikaciju. Podržava string i number (interno uvijek double tj. Python float) tipove te 
standardne aritmetičke i logičke operatore iz C-a (uključujući i ternarni). Posebni dodaci:
    * tip podataka koji daje indikaciju razine jestivosti ili razine otrovnosti/toksičnosti (postoji samo konačan skup za selekciju ovih vrijednosti);
    * tip podataka koji reprezentira relevantne biomarkere/otiske/DNA
    * tip podatka koji reprezentira hijerarhiju; ovo služi za formalno smještanje pojedinih gljiva unutar Linneove ili slične (najvjerojatnije složenije)
    taksonomije (varijanta, vrsta, rod, familija,...)
    ==TRI GLAVNA NOVA OPERATORA==
    * operator mutacije dodjeljenog DNA. Npr. ⥼fungus; specificira da se gljiva 'fungus' mutira po konfiguriranoj distribuciji (pri njenoj konstrukciji)
    (https://en.wikipedia.org/wiki/Genetic_operator)
    (https://archive.org/details/geneticprogrammi0000koza/page/n13/mode/2up)
    * operator križanja. Npr. fungus1 ⊗ fungus2; obavlja križanje dvije gljive i vraća njihovo "dijete"
    * operator selekcije. Npr. [fungus1,fungus2,fungus3]⊙; odabire gljivu iz liste po određenom (interno parametrizabilnom) kriteriju. Ovaj operator
    radi samo nad *listama* jedinki! Općenito želimo da sva tri također rade nad listama radi potpunosti.
    * deklaracija gljive: na neki način i ovo je
    operator (a la operator new u C++u) koji pripremi sve potrebne info o gljivi: hrvatsko ime, stručno latinsko ime,
    klasifikaciju (hijerarhija), mjesto pronalaska, datum, masa,... TODO: što sve tu treba? 
    * operator deklaracije hijerarhije: ovo služi da proglasi neku varijablu hijerarhijom, kako bi se ona onda mogla koristiti pri deklaraciji pojedine gljive.
    Sa hijerarhijama se *ne može* raditi izvan varijabli, tj. one ne mogu biti literali (unose se peacemeal)!
    * operator dodavanja novog elementa hijerarhije u već postojeću: ako je hijerarhija u varijabli 'hij', onda hij.fam = 'famxyz';
    mijenja (ili dodaje, ako familija nije prethodno bila dodijeljena) 'famxyz' kao novu familiju hijerarhije 'hij'.
    * _svi_ objekti (osim taksonomija)
      su imutabilni na razini jezika, ali kompletno mutabilni u smislu genetskih operatora koji se nad njima mogu izvoditi
    
    
Aritmetički izrazi ovdje služe kako bi manipulirali onim podacima gljive koji su brojevi i koji onda služe za definiciju pojedine gljive. Dakle, sveukupno
imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
* operator= je overloadan na prirodne načine za: string, number, bool, fungus (deep copy?), tree (deep copy), edibility, dna (shallow copy?),
datetime (deep copy)

*ALTERNATIVNI NAČINI PISANJA OPERATORA: mislim da baš i nema smisla da novi operatori imaju neki kratki simbolički zapis, ali možemo napraviti ovako:
"dugi" zapis je npr. newtree, a "kratki" | ili nešto sl. 

*FILE I/O: builtin funkcije read() i write(), praktički kao u Pythonu; read('datoteka') čita sve iz dane tekstualne datoteke i deserijalizira u
naše interne strukture svakog od mogućih tipova. write('datoteka', obj1, obj2,...) serijalizira objekt 'obj' u danu
tekstualnu datoteku (stvara ju, briše ako postoji). Uočiti da je ovo jedina "funkcija" koja prima varijabilni broj argumenata, t.d. je moguće
lako spremiti cijeli niz objekata.

*KOMENTARI: #
"""

from vepar import *

class T(TipoviTokena):
    EQ, LT, GT, PLUS, MINUS, PUTA, DIV, OTV, ZATV, LVIT, DVIT, LUGL, DUGL, SEMI, COLON, UPIT, COMMA, DOT = '=<>+-*/(){}[];:?,.'
    ASGN, NEQ, LE, GE = ':=', '!=', '<=', '>='
    AND, OR, NOT = 'and', 'or', 'not'
    LET, STRINGTYPE, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME = 'let', 'string', 'number', 'bool', 'fungus', 'tree', 'edibility',
    'dna', 'datetime' # način za eksplicitno deklarirati varijablu nekog builtin tipa npr. number(12) je ekviv. 12. Zagrade su obvezne pri konstrukciji!
    DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible'
    #SPECIES, GENUS, FAMILY, ORDER, CLASS, PHYLUM, KINGDOM = 'spec', 'gen', 'fam', 'ord', 'class', 'phyl', 'king' #
    #^^ovo ne mogu biti zasebni tokeni jer mi statički ne možemo odrediti tip varijable pa da možemo pri parsiranju validirati je li ok pristupanje članovima
    #taksonomijskih objekata (ovo je "dynamically typed language"); koristit ćemo ova posebna *imena* pri izvršavanju, kada znamo da je element
    #kojem se pristupa točka-izrazom upravo tog tipa
    #https://en.wikipedia.org/wiki/Taxonomy_mnemonic   
    MILIGRAM, GRAM, KILOGRAM = 'mg', 'g', 'kg' # jedinice, mogu se koristiti nakon brojeva; jezik podržava pravilno računanje i javlja grešku
    # pri izvođenju ako je u računu s dimenzijama neki element bez eksplicitno navedene jedinice
    FUNCTION = 'function'
    FOR, IF = 'for', 'if'
    TRUE, FALSE = 'true', 'false'
    SETPARAM = 'setParam'  #ovo je builtin funkcija koja služi interaktivnoj izmjeni/prilagodbi globalnihparametara evolucijskih operatora
    # kako bi se dobili željeni
    # populacijski rezultati kroz simulirane generacije gljiva. Sami parametri nisu hardkodirani u jeziku; predaju se kao param:val parovi
    #  i interpreter je dužan nositi se s njima kako spada. Npr. setParam("param1:")

    #class DOT(Token): pass
    class MUTATION(Token): pass
    class CROSSING(Token): pass
    class SELECTION(Token): pass
    class RETURN(Token):
        literal = 'return' #TODO
    class CONTINUE(Token):
        literal = 'continue'
    class BREAK(Token):
        literal = 'break'
    class BROJ(Token):
        def vrijednost(self):
            return float(self.sadržaj)
        def get_list_length(self):
            return -1
    class IME(Token):
        def vrijednost(self):
            symtab = get_symtab(self)
            return symtab[self]
        def get_list_length(self):
            return -2
    class STRING(Token):
        def vrijednost(self):
            ret = ''
            i = 1
            while i < len(self.sadržaj)-1:
                znak = self.sadržaj[i]
                if znak == '\\':
                    idući = self.sadržaj[i+1]
                    if idući == '\\':
                        ret += '\\'
                    elif idući == 't':
                        ret += '\t'
                    elif idući == '\n': # ovo je za prijelaz u novi red kad se stavi \ na samom kraju linije, što *ne smije* rezultirati u \n u samom stringu!
                        pass
                    else:
                        ret += idući
                    i += 2
                else:
                    ret += znak
                    i += 1
            return ret
        def get_list_length(self):
            return -1
    class DATUM(Token):
        def vrijednost(self):
            try:
                return [int(dio) for dio in self.sadržaj.split('.')]
            except ValueError:
                raise SemantičkaGreška('Krivi format datuma')
            
        def get_list_length(self):
            return -1
        
        def validiraj(self):
            dijelovi = self.vrijednost()
            if dijelovi[0] < 0 or dijelovi[0] > 31 or dijelovi[1] > 12 or dijelovi[1] < 1 or dijelovi[2] < 1000 or dijelovi[2] > 9999:
                raise SemantičkaGreška('Nemoguć datum')
            
            return True
            
    class READ(Token):
        literal = 'read'
        def validate_call(self, *args):
            if len(args) != 0:
                raise SintaksnaGreška('read funkcija ne prima argumente')
        def get_list_length(self):
            return -2
    class WRITE(Token):
        literal = 'write'
        def get_list_length(self):
            return -1

alias = {'⥼': T.MUTATION, 'mutate': T.MUTATION, '⊗': T.CROSSING, '⊙': T.SELECTION, 'cross': T.CROSSING, 'select': T.SELECTION}

@lexer
def miko(lex):
    for znak in lex:
        if znak == '#':
            lex * {lambda x: x != '\n'} # moramo ovako jer želimo da bude legalno ostaviti  #    do samog kraja datoteke (tj. datoteka završi u komentaru)
            lex.zanemari()
            continue
        elif znak == '-':
            if znak := lex >= str.isdigit:
                 pass
            else:
                 yield lex.literal(T)
                 continue
        if znak.isdigit():
            lex * {str.isdigit, '.'}
            if lex.sadržaj.count('.') == 3: # poseban slučaj za datume, oni se mogu odmah lexati kao takvi: 26.3.2023. Ali jasno treba dodatan check u parseru...
                if len(lex.sadržaj) < 6:
                    raise lex.greška('Ilegalan format datuma') #TODO: detaljni error reporting za datume u fazi parsiranja
                else:
                    yield lex.token(T.DATUM)
            else:
                try:
                    test = float(lex.sadržaj)
                except ValueError:
                    raise lex.greška('Ilegalan format broja')
                yield lex.token(T.BROJ)
        elif znak.isalpha():
            lex * {str.isalnum, '_'}
            if lex.sadržaj in alias:
                yield lex.token(alias[lex.sadržaj])
            else:
                yield lex.literal_ili(T.IME)
        elif znak == ':':
            lex >= '='
            yield lex.literal(T)
        elif znak == '<':
            lex >= '='
            lex >= '-'
            yield lex.literal_ili(alias[lex.sadržaj])
        elif znak == '>':
            lex >= '='
            yield lex.literal(T)
        elif znak == '!':
            lex >> '='
            yield lex.literal(T)
        elif znak == '"': # mislim da za ovakav jezik nema smisla podržavati mnoge escape sekvence, jer ovo nije primarno programski jezik
            while True:
                idući = lex - {'\\', '"'}
                if idući == '\\':
                    if lex >= {'\\', '"'}:
                        pass
                    pass
                elif idući == '"':
                    yield lex.token(T.STRING)
                    break                    
        elif znak.isspace():
            lex.zanemari()
        else:
            yield lex.literal_ili(alias[lex.sadržaj])

class GreškaPridruživanja(SintaksnaGreška): """ Greška kada se pridruživanje nađe u izlazu; to ne možemo direktno predstaviti u LL(1) gramatici """

    # * operator mutacije dodjeljenog DNA. Npr. ⥼fungus; specificira da se gljiva 'fungus' mutira po konfiguriranoj distribuciji (pri njenoj konstrukciji)
    # (https://en.wikipedia.org/wiki/Genetic_operator)
    # (https://archive.org/details/geneticprogrammi0000koza/page/n13/mode/2up)
    # * operator križanja. Npr. fungus1 ⊗ fungus2; obavlja križanje dvije gljive i vraća njihovo "dijete"
    # * operator selekcije. Npr. [fungus1,fungus2,fungus3]⊙; 

#imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
#AUTO, STRING, NUMBER, BOOL, FUNGUS, TREE, EDIBILITY, DNA, DATETIME
    #DEADLY, TOXIC1, TOXIC2, EDIBLE = 'deadly', 'toxic1', 'toxic2', 'edible'

## BKG:
# start -> (stmt | fun)+
# type -> (STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME)
# decl -> LET IME | LET asgn
# asgn -> IME ASGN expr
# expr -> cross UPIT expr COLON expr | cross
# cross -> cross CROSSING sel | sel
# sel -> sel SELECTION | mut
# mut -> MUTATION mut | expr2
# expr2 -> expr2 OR expr3 | expr3
# expr3 -> expr3 AND expr5 | expr5
# expr5 -> expr5 EQ expr6 | expr5 NEQ expr6 | expr6
# expr6 -> expr6 LT expr4 | expr6 LE expr4 | expr6 GT expr4 | expr6 GE expr4 | expr4
# expr4 -> (term PLUS)+ term | (term MINUS)+ term | term
# term -> (fact PUTA)+ fact | (fact DIV)+ fact | fact     #TODO: implicitno množenje
# fact -> (bot DOT)+ bot | bot
# bot -> IME (ASGN expr)? | BROJ unit? | STRING | TRUE | FALSE | MINUS bot | NOT bot | OTV expr ZATV | call | cons | edb | datespec | list
# list -> LUGL args? DUGL
# unit -> MILIGRAM | GRAM | KILOGRAM
# cons -> type OTV args? ZATV   # konstruktori za builtin tipove
# fun -> FUNCTION IME OTV params? ZATV LVIT (stmt | RETURN expr SEMI)* DVIT
# params -> (IME COMMA)+ IME | IME
# stmt -> forloop | branch | call SEMI | expr SEMI | decl SEMI |## asgn SEMI
# stmt2 -> CONTINUE SEMI | BREAK SEMI | stmt
# forloop -> FOR IME LVIT stmt2* DVIT | FOR IME stmt2
# branch -> IF OTV expr ZATV LVIT stmt* DVIT | IF OTV expr ZATV LVIT stmt* DVIT ELSE LVIT stmt* DVIT  #izbjegavamo dangling else problem s obveznim {}
# call -> (IME|READ|WRITE) OTV args? ZATV
# setparam_call -> SETPARAM OTV setargs ZATV  #poseban slučaj samo za poziv setParam builtin funkcija koja prima isključivo "keyword" argumente
#(druge funkcije to ne mogu; svi argumenti su pozicijski)
# setargs -> (IME COLON expr COMMA)+ IME COLON expr | IME COLON expr
# args -> (expr COMMA)+ expr | expr
## datespec -> DATUM timespec? | BROJ DOT BROJ DOT BROJ DOT timespec? #ovo bi bilo fleksibilnije pravilo s korisničke strane, ali opet izlazi van LL(1) okvira...
# datespec -> DATUM timespec?
# timespec -> BROJ COLON BROJ (COLON BROJ)? 
# edb -> DEADLY | TOXIC1 | TOXIC2 | EDIBLE

#Parser bi trebao biti dvoprolazni radi lakšeg rada s pozivima funkcija za korisnike: program se izvodi kao Python skripta, dakle  kod može biti u globalnom
#scopeu i otamo pozivati štogod je definirano bilo gdje drugdje (uključujući i interne funkcije tj. konstrukture tipova i read+write). Ali vepar nam baš
#ne olakšava takav dizajn, pa je za sada ovo klasični jednoprolazni parser i stoga sve na što se referiramo mora biti već viđeno

def is_in_symtable(symbol): # provjerava cijeli stog scopeova za utvrditi je li trenutno deklariran symbol; trenutno ne podržavamo ugnježđavanje funkcijskuh
    # blokova, pa je max.dubina stoga 2 (globalan i funkcijski scope)
    for i in range(len(rt.symtab)-1, 0, -1):
        if symbol in rt.symtab[i]:
            return True
        
    return False

def is_function_defined(symbol):
    if symbol in rt.symtab[0]:
        return True
    return False

def get_symtab(symbol):
    for i in range(len(rt.symtab)-1, 0, -1):
        if symbol in rt.symtab[i]:
            return i, rt.symtab[i]
        
def is_arithmetic(tree): # ove stvari su samo za provjeru pri *parsiranju* tj. rade samo na jednoj razini, jer smo pri pozivu u postupku izgradnje izraza
        if tree ^ Unary:
            if tree.op ^ T.MINUS:
                return True
            return False
        elif tree ^ Binary:
            if tree.op ^ {T.PLUS, T.MINUS, T.PUTA, T.DIV}:
                return True
            return False
        elif tree ^ Number or tree ^ Date or tree ^ DateTime or tree ^ T.IME: # TODO: pripazi ovdje na datume i vrijeme --- i oni moraju moći biti u izrazima...
            return True
        elif tree ^ List: 
            # liste mogu sudjelovati u aritmetičkim operatorima, ali im svi elementi moraju biti imena/brojevi i operacije se rade element-po-element
            for el in tree.elements:
                if not is_arithmetic(el):
                    return False
            return True
        elif tree ^ {T.IME, Call, ConstructorCall}:
            return True
        return False

def is_stringetic(tree):
    if tree ^ Unary:
        return False
    elif tree ^ Binary:
        if tree.op ^ T.PLUS:
            return True
        return False
    elif tree ^ Literal and tree.value ^ T.STRING:
        return True
    elif tree ^ List:
        for el in tree.elements:
            if not is_stringetic(el):
                return False
        return True
    elif tree ^ {T.IME, Call, ConstructorCall}:
            return True
    return False

def is_boolean(tree):
    if tree ^ Unary:
        if tree.op ^ T.NOT:
            return True
        return False
    elif tree ^ Binary:
        if tree.op ^ {T.EQ, T.NEQ, T.LE, T.LT, T.GE, T.GT}:
            return True
        return False
    elif tree ^ Literal and tree.value ^ {T.TRUE, T.FALSE}:
        return True
    elif tree ^ List:
        for el in tree.elements:
            if not is_boolean(el):
                return False
        return True
    elif tree ^ {T.IME, Call}:
            return True
    return False

class P(Parser):
    def start(p):
        rt.symtab = list() # želimo leksički scopeane varijable tj. funkcijski lokalne varijable su vidljive samo unutar funkcije ispod pozicije deklariranja
        # i ne smiju se opetovano deklarirati u istoj funkciji; pri izlasku iz funkcije, parser zaboravlja sve njene lokalne varijable. Zato koristimo stog
        functions = []
        statements = []

        while not p > KRAJ:
            if p > T.FUNCTION:
                functions.append(p.fun())
            else:   
                statements.append(*p.stmts())

        if len(statements) == 0:
            raise p.greška('Program je prazan')
        
        return Program(statements, functions)
    
    # fun -> FUNCTION IME OTV params? ZATV LVIT (stmt | RETURN expr SEMI)* DVIT
    def fun(p):
        p >> T.FUNCTION
        name = p >> T.IME
        if is_in_symtable(name):
            raise p.greška('Funkcija ' + name.sadržaj + ' je već definirana')
        params = []
        p >> T.OTV
        if not p >= T.ZATV:
            params = p.params()
            p >> T.ZATV
        p >> T.LVIT
        rt.symtab.append(Memorija()) # push
        body = p.body()
        rt.symtab.pop()
        p >> T.DVIT
        rt.symtab[-1][name] = Function(name, params, body)
        return rt.symtab[-1][name]

    def params(p):
        names = [p >> T.IME]
        while p >= T.COMMA: names.append(p >> T.IME)
        return names
    
    def body(p):
        statements = []
        while el := p > {T.MUTATION, T.RETURN, T.LET, T.FOR, T.IF, T.READ, T.WRITE, T.SETPARAM, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            if el ^ T.RETURN: # TODO: izvrši() za RETURN token
                statements.append(el)
                p >> T.RETURN
            else:
                more = p.stmts()
                #if len(more) == 0:
                  #  raise p.greška('Očekivana naredba')
                statements.append(*more)

        return statements

    def stmts(p, more=True):
        elements = []
        while el := p > {T.MUTATION, T.LET, T.FOR, T.IF, T.READ, T.WRITE, T.SETPARAM, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRING, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            if el ^ T.FOR:
                elements.append(p.forloop())
            elif el ^ T.IF:
                elements.append(p.branch())
            elif el ^ T.READ or el ^ T.WRITE or el ^ T.SETPARAM:
                elements.append(p.call())
                p >> T.SEMI
            elif el ^ T.IME or el ^ T.MUTATION or el ^ T.BROJ or el ^ T.STRING or el ^ T.TRUE or el ^ T.FALSE or el ^ T.MINUS or el ^ T.NOT or el ^ T.OTV or el ^ T.STRINGTYPE or el ^ T.NUMBER or el ^ T.BOOL or el ^ T.FUNGUS or el ^ T.TREE or el ^ T.EDIBILITY or el ^ T.DNA or el ^ T.DATETIME or el ^ T.DEADLY or el ^ T.TOXIC1 or el ^ T.TOXIC2 or el ^ T.EDIBLE or el ^ T.DATUM or el ^ T.LUGL:
                elements.append(p.expr()) #tu su ubačeni i call za user-fun i naredbe pridruživanja; disambiguacija se događa tek u expr() (ne može prije jer LL(1))
                p >> T.SEMI
            elif el ^ T.LET:
                elements.append(p.decl())
                p >> T.SEMI
            if not more:
                break
        # ne hendlamo početni token za `asgn` ovdje jer je on početni i za `expr`; općenito, smatrat ćemo da su i dodjele izrazi, iako nama semantički nisu
        # i to će se razriješiti u odgovarajućoj funkciji
        if not more and len(elements) == 0:
            raise p.greška('Očekivana jedna naredba')
        return Statements(elements)
    
    def stmts2(p, more=True):
        statements = []
        while p > {T.MUTATION, T.LET, T.CONTINUE, T.BREAK, T.FOR, T.IF, T.READ, T.WRITE, T.SETPARAM, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            if el := p >= {T.CONTINUE, T.BREAK}:
                p >> T.SEMI
                statements.append(el)
            else:
                statements.append(*p.stmts(more))

        return Statements(statements)
        
    
    # forloop -> FOR IME LVIT stmt2* DVIT | FOR IME stmt2
    def forloop(p):
        p >> T.FOR
        var = p >> T.IME
        if not is_in_symtable(var):
            raise p.greška('Varijabla ' + var.sadržaj + ' nije definirana')
        idx, symtab = get_symtab(var)
        if symtab[var] ^ Function:
            raise p.greška('U for petlji je ime funkcije umjesto varijable')
        if p >= T.LVIT:
            stmts = p.stmts2()
            p >> T.DVIT
            return ForLoop(var, stmts)
        else:
            stmt = p.stmts2(False)
            return ForLoop(var, stmt)
        
# branch -> IF OTV expr ZATV LVIT stmt* DVIT | IF OTV expr ZATV LVIT stmt* DVIT ELSE LVIT stmt* DVIT
    def branch(p):
        p >> T.IF
        p >> T.OTV
        test = p.expr()
        if not test ^ Binary or not test.op ^ T.LT or not test.op ^ T.LE or not test.op ^ T.GT or not test.op ^ T.GE or not test.op ^ T.EQ or not test.op ^ T.NEQ:
            raise SemantičkaGreška('Uvjeti za grananje moraju biti bool izrazi')
        p >> T.ZATV
        p >> T.LVIT
        branch1 = p.stmts()
        p >> T.DVIT
        if p >= T.ELSE:
            p >> T.LVIT
            branch2 = p.stmts()
            p >> T.DVIT
            return ComplexBranch(test, branch1, branch2)
        else:
            return SimpleBranch(test, branch1)
        
        # call -> (IME|READ|WRITE) OTV args? ZATV
        # setparam_call -> SETPARAM OTV setargs ZATV
# setargs -> (IME COLON expr COMMA)+ IME COLON expr | IME COLON expr
    def call(p):
        fun = None
        if fun := p >= T.IME:
            if not is_function_defined(fun): # koristimo ovu zasebnu funkciju za funkcijske simbole jer oni moraju biti samo u globalnom scopeu
                raise p.greška('Funkcija ' + fun.sadržaj + ' nije definirana')
            idx, symtab = get_symtab(fun)
            if not symtab[fun] ^ Function:
                raise p.greška('Očekivana funkcija za poziv')
            fun = symtab[fun]
        elif fun := p >= T.SETPARAM:
            p >> T.OTV
            args = {}
            while p >= T.COMMA:
                key = p >> T.IME
                if key in args:
                    raise SemantičkaGreška('Već ste naveli vrijednost parametra ' + key.sadržaj)
                p >> T.COLON
                val = p.expr()
                args[key] = val
            p >> T.ZATV
            return Call(fun, args)
        else: 
            fun = p >> {T.READ, T.WRITE}
        
        p >> T.OTV
        args = []
        if p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            args = p.args()
        fun.validate_call(args)
        p >> T.ZATV
        return Call(fun, args)
    
# expr -> cross UPIT expr COLON expr | cross
# cross -> cross CROSSING sel | sel
# sel -> sel SELECTION | mut
# mut -> MUTATION mut | expr2
# expr2 -> expr2 OR expr3 | expr3

    def expr(p):
        left = p.cross()
        if p >= T.UPIT:
            middle = p.expr()
            p >> T.COLON
            right = p.expr()
            if middle ^ Assignment or right ^ Assignment:
                raise GreškaPridruživanja
            return Ternary(left, middle, right)
        else:
            return left
        
    def cross(p):
        tree = p.sel()
        while op := p >= T.CROSSING:
            tree = Binary(op, tree, p.sel())
            if tree.right ^ Assignment:
                raise GreškaPridruživanja
        return tree
    
    def sel(p):
        tree = p.mut()
        if op := p >= T.SELECTION:
            return Unary(op, tree)
        return tree
    
    def mut(p):
        if op := p >> T.MUTATION:
            return Unary(op, p.mut())
        return p.expr2()
        
    def expr2(p):
        tree = p.expr3()
        while op := p >= T.OR:
            tree = Binary(op, tree, p.expr3())
            if tree.right ^ Assignment:
                raise GreškaPridruživanja
            #if tree.right ^ Nary:
                #if tree.right[0][1][0][1][0] ^ Assignment:
                #    raise GreškaPridruživanja

        return tree
    
# expr3 -> expr3 AND expr5 | expr5
# expr5 -> expr5 EQ expr6 | expr5 NEQ expr6 | expr6
# expr6 -> expr6 LT expr4 | expr6 LE expr4 | expr6 GT expr4 | expr6 GE expr4 | expr4
# expr4 -> (term PLUS)+ term | (term MINUS)+ term | term
    
    def expr3(p):
        tree = p.expr5()
        while op := p >= T.AND:
            tree = Binary(op, tree, p.expr5())
            #if tree.right[0][1][0][1][0] ^ Assignment:
            if tree.right ^ Assignment:
                raise GreškaPridruživanja
        return tree
    
    def expr5(p):
        tree = p.expr6()
        while op := p >= {T.EQ, T.NEQ}:
            tree = Binary(op, tree, p.expr6())
            if tree.right ^ Assignment:
                raise GreškaPridruživanja
        return tree
    
    def expr6(p):   #TODO: bool typechecking here
        tree = p.expr4()
        while op := p >= {T.LT, T.LE, T.GT, T.GE}:
            tree = Binary(op, tree, p.expr4())
            if tree.right ^ Assignment:
                raise GreškaPridruživanja
        return tree
    
    def expr4(p):
        terms = [[T.PLUS, p.term()]]
        while op := p >= {T.PLUS, T.MINUS}:
            if terms[-1][1] ^ Assignment:
                raise GreškaPridruživanja
            terms.append([op, p.term()])
        if len(terms) == 1:
            return terms[0][1]
        else:
            any_lists = False
            stringetic = True
            arithmetic = True
            # dopuštamo samo + nad stringovima, što uključuje i liste stringova. NIJE dozvoljen + nad stringom i brojem; nužno je eksplicitno konvertirati
            for op,item in terms:
                if not is_stringetic(item):
                    stringetic = False
                if not is_arithmetic(item):
                    arithmetic = False
                if item ^ List:
                    any_lists = True
            if arithmetic and stringetic:
                raise SemantičkaGreška('Zbrajanje broja i stringa nije dopustivo; ako želite konkatenaciju, koristite string(brojevni izraz)')
            if stringetic:
                for op,ign in terms:
                    if not op ^ T.PLUS:
                        raise SemantičkaGreška('Samo zbrajanje (konkatenacija) je podržano nad stringovima')
            if any_lists:
                len = None
                for ign,item in terms:
                    tmp = item.get_list_length()
                    if tmp != -2:
                        if len is None:
                            len = tmp
                        else:
                            if len != tmp:
                                raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')

        return Nary(terms)
    
    def term(p):
        facts = [[T.PUTA, p.fact()]]
        while op := p >= {T.PUTA, T.DIV}:
            if facts[-1][1] ^ Assignment:
                raise GreškaPridruživanja
            facts.append([op, p.fact()])
        if len(facts) == 1:
            return facts[0][1]
        else:
            any_lists = False
            for ign,item in facts: # ako se liste pojavljuju u množenju/dijeljenju, to je dopustivo i u proizvoljnoj kombinaciji sa skalarima, s prirodnom
                # (lijevo asociranom) interpretacijom, ali sve liste moraju biti jednake duljine
                if not is_arithmetic(item):
                    raise SemantičkaGreška('Množenje i dijeljenje moguće samo s brojevnim operandima/listama')
                if item ^ List:
                    any_lists = True
            if any_lists:
                len = None
                for ign,item in facts:
                    tmp = item.get_list_length()
                    if tmp != -2:
                        if len is None:
                            len = tmp
                        else:
                            if len != tmp:
                                raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
        return Nary(facts)
    
    def fact(p):
        bots = [p.bot()]
        while p >= T.DOT: 
            if bots[-1] ^ Assignment:
                raise GreškaPridruživanja('Pridruživanje nije izraz') # tu detektiramo krive izraze;
            #ovo se radi kad god može biti više operanada jer to onda ne može biti pridruživanje (koje jest jedan jedini pseudoizraz)
            bots.append(p.bot())
        if len(bots) > 1:
            if not bots[0] ^ ConstructorCall and not bots[0] ^ T.IME:
                raise SemantičkaGreška('Početak liste s točkama mora biti konstruiran objekt ili ime')
            for item in bots:
                if not item ^ T.IME:
                    raise SemantičkaGreška('Samo imena svojstava smiju biti između točaka')
        return DotList.ili_samo(bots)
    
    # bot -> IME (ASGN expr)? | BROJ unit? | STRING | TRUE | FALSE | MINUS bot | NOT bot | OTV expr ZATV | call | cons | edb | datespec | list
    # cons -> type OTV args? ZATV   # konstruktori za builtin tipove
    # type -> (STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME)
    def bot(p):
        if var := p > T.IME:
            if not is_in_symtable(var):
                raise p.greška('Ime ' + var.sadržaj + ' nije viđeno do sada')
            idx, symtab = get_symtab(var)
            if symtab[var] ^ Function: # ovo mora biti poziv funkcije 'var'
                return p.call()
            else: # inače je čisto pridruživanje varijable ili čisto pojavljivanje varijable (po mogućnosti unutar složenijeg izraza)
                if p >= T.ASGN:
                    return Assignment(var, p.expr())
                else:
                    return var
        elif p > {T.READ, T.WRITE, T.SETPARAM}:
            return p.call()
        elif num := p >= T.BROJ:
            unit = p >= {T.MILIGRAM, T.GRAM, T.KILOGRAM}
            return Number(num, unit)
        elif literal := p >= {T.STRING, T.TRUE, T.FALSE}:
            return Literal(literal)
        elif op := p >= {T.MINUS, T.NOT}:
            return Unary(op, p.bot())
        elif p >= T.OTV:
            subexpr = p.expr()
            p >> T.ZATV
            return subexpr
        elif p > {T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME}:
            return p.cons()
        elif p > T.DATUM:
            return p.datespec()
        elif p > T.LUGL:
            return p.list()
        else:
            return p.edb()
# decl -> LET IME | LET asgn
    def cons(p):
        type = p >> {T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME}
        p >> T.OTV
        args = []
        if p > {T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            args = p.args()   # TODO: dodati validatore za pozive konstruktora na baznim tipovima + validatore za pozive user funkcija
        p >> T.ZATV
        type.validate_call(args)
        return ConstructorCall(type, args)
    
    def datespec(p):
        date = p >> T.DATUM
        date.validiraj() # je li ovo ok datum, čisto sintaktički?
        minutes = 0
        seconds = 0
        if hour := p >= T.BROJ:
            p >> T.COLON
            minutes = p >> T.BROJ
            if p >= T.COLON:
                seconds = p >> T.BROJ
            return DateTime(date, hour, minutes, seconds)
        else:
            return Date(date)

    def list(p):
        p >> T.LUGL
        if not p > {T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            return List([])
        exprs = [p.expr()]
        while p >= T.COMMA: exprs.append(p.expr())
        return List(exprs)
    
    def edb(p):
        kind = p >> {T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE}
        return Edibility(kind)

    def decl(p):
        p >> T.LET
        var = p >> T.IME
        if is_in_symtable(var):
            idx, symtab = get_symtab(var)
            if idx == len(rt.symtab) - 1: # ne skrivamo vanjsku varijablu već je redeklariramo unutar istog scopea, što ne dozvoljavamo
                raise p.greška('Varijabla ' + var.sadržaj + ' je već deklarirana u ovom dosegu')
        rt.symtab[-1][var] = var

        if p >= T.ASGN:
            return Assignment(var, p.expr())
        else:
            return Declaration(var)

    def args(p):
        exprs = [p.expr()]
        while p >= T.COMMA: exprs.append(p.expr())
        return exprs

        
            

class Program(AST):
    statements: ...
    functions: ...

    def izvrši(self):
        rt.okolina = rt.symtab[0] # tu držimo vrijednosti vidljivih varijabli; na početku su to samo globalne, a svaki pojedini poziv stvara podokvir tj. nadodaje
        # stvari koje onda skida kada završi s izvršavanjem pozvane funkcije
        for stmt in self.statements:
            stmt.izvrši()

class Function(AST):
    name: ...
    parameter_names: ...
    body: ...

    def validate_call(self, *args):
        if len(self.parameter_names) != len(args):
            raise SemantičkaGreška('Broj argumenata kod poziva funkcije' + self.name.sadržaj + ' treba biti ' + len(self.parameter_names))

    def izvrši(self, *args):
        a

class Statements(AST):
    statements: ...

class ForLoop(AST):
    loop_variable: ...
    body_statements: ...

class SimpleBranch(AST):
    test_variable: ...
    branch1_statements: ...

class ComplexBranch(SimpleBranch):
    branch2_statements: ...

class Call(AST):
    function: ...
    arguments: ...

    def get_list_length(self):
        return -2

class Ternary(AST):
    left: ...
    middle: ...
    right: ...

class Binary(AST):
    op: ...
    left: ...
    right: ...

    def get_list_length(self): # daje duljinu listi ako postoje u ikojem argumentu; -1 ako ne postoje (pretpostavka je da je izraz dobro formiran) i
        # -2 ako to nije statički odlučivo
        tmp = self.left.get_list_length()
        if tmp == -1:
            return -1
        tmp = self.right.get_list_length()
        if tmp == -1:
            return -1
        return tmp

class Unary(AST):
    op: ...
    child: ...

    def get_list_length(self):
        tmp = self.child.get_list_length()
        if tmp == -1:
            return -1
        return tmp

class Nary(AST):
    pairs: ... # (op,expr) pairs

    def get_list_length(self):
        for op,expr in self.pairs:
            tmp = expr.get_list_length()
            if tmp == -1:
                return -1
        return tmp

class DotList(AST):
    elements: ...

class Assignment(AST):
    variable: ...
    expression: ...

class Number(AST):
    value: ...
    unit: ...

    def get_list_length(self):
        return -1

class Literal(AST):
    value: ...

    def get_list_length(self):
        return -1

class ConstructorCall(AST):
    type: ...
    arguments: ...

    def get_list_length(self):
        return -1

class Date(AST):
    date: ... #(day,month,year) triple

    def get_list_length(self):
        return -1

class DateTime(Date):
    hours: ...
    minutes: ...
    seconds: ...

    def get_list_length(self):
        return -1

class List(DotList):
    def get_list_length(self):
        return len(self.elements)

class Edibility(AST):
    kind: ...

    def get_list_length(self):
        return -1

class Declaration(AST):
    variable: ...


