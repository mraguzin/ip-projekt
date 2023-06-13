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

    class MUTATION(Token): pass
    class CROSSING(Token): pass
    class SELECTION(Token): pass

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
                    lex.čitaj()
                elif idući == '"':
                    yield lex.token(T.STRING)
                    break                    
        elif znak.isspace():
            lex.zanemari()
        else:
            try:
                if lex.sadržaj in alias:
                    yield lex.token(alias[lex.sadržaj])
                else:
                    yield lex.literal(T)
            except KeyError:
                raise lex.greška()
            
miko('[]')