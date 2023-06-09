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
    * _svi_ objekti (osim taksonomija, koje se jedino i mogu kompletno izgraditi preko . operatora)
      su imutabilni na razini jezika, ali kompletno mutabilni u smislu genetskih operatora koji se nad njima mogu izvoditi
    
    
Aritmetički izrazi ovdje služe kako bi manipulirali onim podacima gljive koji su brojevi i koji onda služe za definiciju pojedine gljive. Dakle, sveukupno
imamo tipove: string, number, bool, fungus, tree, edibility, dna, datetime
* operator= je overloadan na prirodne načine za: string, number, bool, fungus (shallow), tree (deep copy), edibility, dna (shallow),
datetime (deep copy)

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
    LET = 'let'
    # način za eksplicitno deklarirati varijablu nekog builtin tipa npr. number(12) je ekviv. 12. Zagrade su obvezne pri konstrukciji!
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
    class STRINGTYPE(Token): # ovo stavljamo ovdje radi mogućnosti provjera konstruktorskih argumenata
        literal = 'string'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class NUMBER(Token):
        literal = 'number'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class BOOL(Token):
        literal = 'bool'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class FUNGUS(Token):
        literal = 'fungus'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class TREE(Token):
        literal = 'tree'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class EDIBILITY(Token):
        literal = 'edibility'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class DNA(Token):
        literal = 'dna'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
    class DATETIME(Token):
        literal = 'datetime'
        def validate_call(self, *args):
            if len(args) != 1:
                return False
            return True
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
            return None
    class IME(Token):
        def vrijednost(self):
            symtab = get_symtab(self)
            return symtab[self]
        def get_list_length(self):
            return None
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
            return None
    class DATUM(Token):
        def vrijednost(self):
            try:
                return [int(dio) for dio in self.sadržaj.split('.')]
            except ValueError:
                raise SemantičkaGreška('Krivi format datuma')
            
        def get_list_length(self):
            return None
        
        def validiraj(self):
            dijelovi = self.vrijednost()
            if dijelovi[0] < 0 or dijelovi[0] > 31 or dijelovi[1] > 12 or dijelovi[1] < 1 or dijelovi[2] < 1000 or dijelovi[2] > 9999:
                raise SemantičkaGreška('Nemoguć datum')
            
            return True
            
    class READ(Token):
        literal = 'read'
        def validate_call(self, *args):
            if len(args) != 1:
                raise SintaksnaGreška('read funkcija očekuje jedan argument: ime tekstualne datoteke za pročitati')
        def get_list_length(self):
            return None
    class WRITE(Token):
        literal = 'write'
        def validate_call(self, *args):
            if len(args) < 2:
                raise SemantičkaGreška('write funkcija očekuje bar dva argumenta: 1:datoteku, 2: objekt, više objekata ili listu objekata za zapisati')
        def get_list_length(self):
            return None

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
            try:
                yield lex.literal_ili(alias[lex.sadržaj])
            except KeyError:
                raise lex.greška()

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
# type -> STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME
# nodna -> STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DATETIME
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
# cons -> type OTV args? ZATV | DNA LUGL params DUGL | DNA OTV IME ZATV  # konstruktori za builtin tipove
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
# (sigurno ne želimo prototipove)

def is_in_symtable(symbol): # provjerava cijeli stog scopeova za utvrditi je li trenutno deklariran symbol; ne podržavamo ugnježđavanje funkcijskih
    # blokova, pa je max.dubina stoga 2 (globalan i funkcijski scope)
    for i in range(len(rt.symtab)-1, 0, -1):
        if symbol in rt.symtab[i]:
            return True
        
    return False

def is_function_defined(symbol):
    if symbol in rt.funtab:
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
        elif tree ^ Nary and tree.pairs[0][0] ^ {T.PLUS, T.MINUS, T.PUTA, T.DIV}:
            return True
        elif tree ^ {Number, T.IME, Call}: # TODO: pripazi ovdje na datume i vrijeme --- i oni moraju moći biti u izrazima...
            return True
        elif tree ^ ConstructorCall and not tree.type ^ T.NUMBER:
            raise SemantičkaGreška('Očekivan konstruktor broja')
        elif tree ^ List:
            # liste mogu sudjelovati u aritmetičkim operacijama, ali im svi elementi moraju biti imena/brojevi i operacije se rade element-po-element
            for el in tree.elements:
                if not is_arithmetic(el):
                    return False
            return True
        #elif tree ^ {T.IME, Call, ConstructorCall}:
         #   return None # statički neodlučivo
        return False

def is_datetime(tree):
        if tree ^ Unary:
            return False
        elif tree ^ Nary and tree.pairs[0][0] ^ T.MINUS:
            return True
        elif tree ^ {Date, DateTime, T.IME, Call}:
            return True
        elif tree ^ ConstructorCall and not tree.type ^ T.DATETIME:
            raise SemantičkaGreška('Očekivan konstruktor datuma')
        elif tree ^ List:
            for el in tree.elements:
                if not is_datetime(el):
                    return False
            return True
        return False

def is_stringetic(tree):
    if tree ^ Unary:
        return False
    elif tree ^ Nary and tree.pairs[0][0] ^ T.PLUS:
        return True
    elif tree ^ Literal and tree.value ^ T.STRING:
        return True
    elif tree ^ List:
        for el in tree.elements:
            if not is_stringetic(el):
                return False
        return True
    elif tree ^ {T.IME, Call}:
            return True
    elif tree ^ ConstructorCall and not tree.type ^ T.STRINGTYPE:
        raise SemantičkaGreška('Očekivan konstruktor stringa')
    return False

def is_boolean(tree):
    if tree ^ Unary:
        if tree.op ^ T.NOT:
            return True
        return False
    elif tree ^ Binary:
        if tree.op ^ {T.AND, T.OR, T.EQ, T.NEQ, T.LE, T.LT, T.GE, T.GT}:
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
    elif tree ^ ConstructorCall and not tree.type ^ T.BOOL:
        raise SemantičkaGreška('Očekivan konstruktor boola')
    return False

class P(Parser):
    def start(p):
        rt.symtab = list() # želimo leksički scopeane varijable tj. funkcijski lokalne varijable su vidljive samo unutar funkcije ispod pozicije deklariranja
        # i ne smiju se opetovano deklarirati u istoj funkciji; pri izlasku iz funkcije, parser zaboravlja sve njene lokalne varijable. Zato koristimo stog
        rt.funtab = Memorija() # tu držimo samo (globalne) funkcije
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
        #if is_in_symtable(name):
        if name not in rt.funtab:
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
        #rt.symtab[-1][name] = Function(name, params, body)
        rt.funtab[name] = Function(name, params, body)
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
        #if symtab[var] ^ Function:
         #   raise p.greška('U for petlji je ime funkcije umjesto varijable')
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
        #if not test ^ Binary or not test.op ^ T.LT or not test.op ^ T.LE or not test.op ^ T.GT or not test.op ^ T.GE or not test.op ^ T.EQ or not test.op ^ T.NEQ:
        if not is_boolean(test):
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
                raise SemantičkaGreška('Funkcija ' + fun.sadržaj + ' nije definirana')
            #idx, symtab = get_symtab(fun)
            #if not symtab[fun] ^ Function:
                #raise p.greška('Očekivana funkcija za poziv')
            #fun = symtab[fun]
            fun = rt.funtab[fun]
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
            if left ^ Assignment or middle ^ Assignment or right ^ Assignment:
                raise GreškaPridruživanja
            return Ternary(left, middle, right)
        else:
            return left
        #TODO: trebamo li dozvoliti višestruka pridruživanja oblika a=b=c=d? To bi mogli posebnim pravilom za stmt...
    def cross(p):
        tree = p.sel()
        while op := p >= T.CROSSING:
            tree = Binary(op, tree, p.sel())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_fungus(tree):
                raise SemantičkaGreška('Samo se liste gljiva mogu križati')
        return tree
    
    def sel(p):
        tree = p.mut()
        if op := p >= T.SELECTION:
            if not is_fungus(tree):
                raise SemantičkaGreška('Samo se liste gljiva mogu selektirati')
            return Unary(op, tree)
        return tree
    
    def mut(p):
        if op := p >> T.MUTATION:
            tmp = p.mut()
            if not is_fungus(tmp):
                raise SemantičkaGreška('Samo se gljive ili njihove liste mogu mutirati')
            return Unary(op, p.mut())
        return p.expr2()
        
    def expr2(p):
        tree = p.expr3()
        while op := p >= T.OR:
            tree = Binary(op, tree, p.expr3())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_boolean(tree.left) or not is_boolean(tree.right):
                raise SemantičkaGreška('Logičke operacije podržane samo nad boolean izrazima/vrijednostima')
            if tree.left ^ List or tree.right ^ List:
                raise SemantičkaGreška('Liste se ne mogu uspoređivati') 

        return tree
    
# expr3 -> expr3 AND expr5 | expr5
# expr5 -> expr5 EQ expr6 | expr5 NEQ expr6 | expr6
# expr6 -> expr6 LT expr4 | expr6 LE expr4 | expr6 GT expr4 | expr6 GE expr4 | expr4
# expr4 -> (term PLUS)+ term | (term MINUS)+ term | term
    
    def expr3(p):
        tree = p.expr5()
        while op := p >= T.AND:
            tree = Binary(op, tree, p.expr5())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_boolean(tree.left) or not is_boolean(tree.right):
                raise SemantičkaGreška('Logičke operacije podržane samo nad boolean izrazima/vrijednostima')
            if tree.left ^ List or tree.right ^ List:
                raise SemantičkaGreška('Liste se ne mogu uspoređivati') 
        return tree
    
    def expr5(p):
        tree = p.expr6()
        while op := p >= {T.EQ, T.NEQ}:
            tree = Binary(op, tree, p.expr6())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if tree.left ^ List or tree.right ^ List:
                raise SemantičkaGreška('Liste se ne mogu uspoređivati') #TODO: ovo bi mogli dopustiti, ali zahtijeva zasebno rekurzivno testiranje
            #elemenata listi u typecheckeru...
            
        return tree
    
    def expr6(p):   #TODO: bool typechecking here
        tree = p.expr4()
        while op := p >= {T.LT, T.LE, T.GT, T.GE}:
            tree = Binary(op, tree, p.expr4())
            if tree.left ^ Assignment or tree.right ^ Assignment:
                raise GreškaPridruživanja
            if not is_arithmetic(tree.left) and not is_arithmetic(tree.right):
                raise SemantičkaGreška('<, >, <= i >= su upotrebljivi samo nad brojevnim izrazima/vrijednostima')
            if tree.left ^ List or tree.right ^ List:
                raise SemantičkaGreška('Liste se ne mogu uspoređivati') #TODO: ovo bi mogli dopustiti, ali zahtijeva zasebno rekurzivno testiranje
            #elemenata listi u typecheckeru...
        return tree
    
    def expr4(p):
        terms = [[T.PLUS, p.term()]]
        arithmetic = True
        stringetic = True
        len = terms[-1][1].get_list_length()
        while op := p >= {T.PLUS, T.MINUS}:
            if terms[-1][1] ^ Assignment:
                raise GreškaPridruživanja
            #if not is_arithmetic(terms[-1][1]) and not is_stringetic(terms[-1][1]):
            if not arithmetic and not stringetic:
                raise SemantičkaGreška('+ i - dozvoljeno samo nad brojevima i stringovima')
            if not is_arithmetic(terms[-1][1]):
                if not stringetic:
                    raise SemantičkaGreška('Aritmetičke operacije s brojem mogu biti samo s drugim brojem')
                arithmetic = False
            if not is_stringetic(terms[-1][1]):
                if not arithmetic:
                    raise SemantičkaGreška('Konkatenacija stringa moguća samo s drugim stringom')
                stringetic = False
            if op ^ T.MINUS:
                if not arithmetic:
                    raise SemantičkaGreška('Oduzimanje nije podržano nad stringovima')
                stringetic = False
            if terms[-1][1] ^ List:
                if len != terms[-1][1].get_list_length():
                    raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
            terms.append([op, p.term()])
        if len(terms) == 1:
            return terms[0][1]
        else: #TODO: bilo bi lijepo kada ne bi morali ponoviti cijeli ovaj blok ovdje... do while?
            if terms[-1][1] ^ Assignment:
                raise GreškaPridruživanja
            if not arithmetic and not stringetic:
                raise SemantičkaGreška('+ i - dozvoljeno samo nad brojevima i stringovima')
            if not is_arithmetic(terms[-1][1]):
                if not stringetic:
                    raise SemantičkaGreška('Aritmetičke operacije s brojem mogu biti samo s drugim brojem')
                arithmetic = False
            if not is_stringetic(terms[-1][1]):
                if not arithmetic:
                    raise SemantičkaGreška('Konkatenacija stringa moguća samo s drugim stringom')
                stringetic = False
            if op ^ T.MINUS:
                if not arithmetic:
                    raise SemantičkaGreška('Oduzimanje nije podržano nad stringovima')
                stringetic = False
            if terms[-1][1] ^ List:
                if len != terms[-1][1].get_list_length():
                    raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
        return Nary(terms)
    
    def term(p): #TODO: tu je nužan dodatan check na kraju (nije moguće ovdje prilikom izgradnje AST-a) koji provjerava konzistentnost rada s jedinicama
        facts = [[T.PUTA, p.fact()]]
        len = facts[-1][1].get_list_length()
        while op := p >= {T.PUTA, T.DIV}:
            if not is_arithmetic(facts[-1][1]):
                raise SemantičkaGreška('Množenje i dijeljenje moguće samo s brojevnim operandima/listama')
            facts.append([op, p.fact()])
            if facts[-1][1] ^ List:
                if facts[-1][1].get_list_length() != len:
                    raise SemantičkaGreška('Aritmetika nad listama nejednake duljine')
                # ako se liste pojavljuju u množenju/dijeljenju, to je dopustivo i u proizvoljnoj kombinaciji sa skalarima, s prirodnom
                # (lijevo asociranom) interpretacijom, ali sve liste moraju biti jednake duljine ("broadcasting")
        if len(facts) == 1:
            return facts[0][1]
        if not is_arithmetic(facts[-1][1]):
            raise SemantičkaGreška('Množenje i dijeljenje moguće samo s brojevnim operandima/listama')
        return Nary(facts)
    
    def fact(p):
        bots = [p.bot()]
        while p >= T.DOT: 
            bots.append(p.bot())
        if len(bots) > 1:
            if not bots[0] ^ ConstructorCall and not bots[0] ^ T.IME:
                raise SemantičkaGreška('Početak liste s točkama mora biti konstruiran objekt ili ime')
            for item in bots[1:]:
                if not item ^ T.IME:
                    raise SemantičkaGreška('Samo imena svojstava smiju biti između točaka')
        return DotList.ili_samo(bots)
    
    # bot -> IME (ASGN expr)? | BROJ unit? | STRING | TRUE | FALSE | MINUS bot | NOT bot | OTV expr ZATV | call | cons | edb | datespec | list
    # cons -> type OTV args? ZATV   # konstruktori za builtin tipove
    # type -> (STRINGTYPE | NUMBER | BOOL | FUNGUS | TREE | EDIBILITY | DNA | DATETIME)
    def bot(p):
        if var := p > T.IME:
            if is_in_symtable(var):# inače je čisto pridruživanje varijable ili čisto pojavljivanje varijable (po mogućnosti unutar složenijeg izraza)
                if p >= T.ASGN:
                    return Assignment(var, p.expr())
                else:
                    return var
            idx, symtab = get_symtab(var)
            # ovo mora biti poziv funkcije 'var'
            if var in rt.funtab:
                return p.call()
            else: 
                raise p.greška('Ime ' + var.sadržaj + ' nije viđeno do sada')   
        elif p > {T.READ, T.WRITE, T.SETPARAM}:
            return p.call()
        elif num := p >= T.BROJ:
            unit = p >= {T.MILIGRAM, T.GRAM, T.KILOGRAM}
            return Number(num, unit)
        elif literal := p >= {T.STRING, T.TRUE, T.FALSE}:
            return Literal(literal)
        elif op := p >= {T.MINUS, T.NOT}:
            below = p.bot()
            if op ^ T.MINUS and not is_arithmetic(below):
                raise SemantičkaGreška('Negirati se mogu samo brojevni izrazi')
            if op ^ T.NOT and not is_boolean(below):
                raise SemantičkaGreška('Logička negacija moguća samo na bool izrazima')
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
# cons -> type OTV args? ZATV | DNA LUGL params DUGL | DNA OTV IME ZATV 
    def cons(p):
        type = p >> {T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME}
        p >> T.OTV
        if type ^ T.DNA: # poseban slučaj za konstrukciju DNA: može kao DNA(ATCGGA) ili kao DNA([A,T,C,G,G,A])
            if p >= T.LUGL:
                bases = p.params()
                # validiraj da su imena samo 'A', 'T', 'C' ili 'G'
                for base in bases:
                    if base.sadržaj not in {'A', 'T', 'C', 'G'}:
                        raise SintaksnaGreška('Netočan format DNA: očekivani nukelotidi iz {A,T,C,G}')
                p >> T.DUGL
                p >> T.ZATV
                values = [base.sadržaj for base in bases]
                return DNA(values)
            elif bases := p >> T.IME:
                for base in bases.sadržaj:
                    if base not in {'A', 'T', 'C', 'G'}:
                        raise SintaksnaGreška('Netočan format DNA: očekivani nukelotidi iz {A,T,C,G}')
                p >> T.ZATV
                return DNA(bases)
        args = []
        if p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
            args = p.args()
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
        if not p > {T.MUTATION, T.IME, T.BROJ, T.STRING, T.TRUE, T.FALSE, T.MINUS, T.NOT, T.OTV, T.STRINGTYPE, T.NUMBER, T.BOOL, T.FUNGUS, T.TREE, T.EDIBILITY, T.DNA, T.DATETIME, T.DEADLY, T.TOXIC1, T.TOXIC2, T.EDIBLE, T.DATUM, T.LUGL}:
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
        return None

class Ternary(AST):
    left: ...
    middle: ...
    right: ...

class Binary(AST):
    op: ...
    left: ...
    right: ...

    def get_list_length(self):
        return self.left.get_list_length()

class Unary(AST):
    op: ...
    child: ...

    def get_list_length(self):
        return self.child.get_list_length()

class Nary(AST):
    pairs: ... # (op,expr) pairs

    def get_list_length(self):
        return self.pairs[0][1].get_list_length()

class DotList(AST):
    elements: ...

    def get_list_length(self):
        return None

class Assignment(AST):
    variable: ...
    expression: ...

class Number(AST):
    value: ...
    unit: ...

    def get_list_length(self):
        return None

class Literal(AST):
    value: ...

    def get_list_length(self):
        return None

class ConstructorCall(AST):
    type: ...
    arguments: ...

    def get_list_length(self):
        return None

class Date(AST):
    date: ... #(day,month,year) triple

    def get_list_length(self):
        return None

class DateTime(Date):
    hours: ...
    minutes: ...
    seconds: ...

    def get_list_length(self):
        return None
    
class DNA(AST):
    bases: ...

class List(DotList):
    def get_list_length(self):
        return len(self.elements)

class Edibility(AST):
    kind: ...

    def get_list_length(self):
        return None

class Declaration(AST):
    variable: ...


