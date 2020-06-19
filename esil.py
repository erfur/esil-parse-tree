import logging
from collections import namedtuple
from contextlib import suppress
from esil_analysis import AnalysisEngine

logger = logging.getLogger('esil')
logging.basicConfig()
logger.setLevel(logging.INFO)

EsilOperator = namedtuple('EsilOperator', 'pop_count internal_name')

esil_operators = {
    '$'     : EsilOperator(pop_count=1, internal_name='esil_interrupt'),
    '$z'    : EsilOperator(pop_count=0, internal_name='esil_zf'),
    '$c'    : EsilOperator(pop_count=1, internal_name='esil_cf'),
    '$b'    : EsilOperator(pop_count=1, internal_name='esil_bf'),
    '$p'    : EsilOperator(pop_count=0, internal_name='esil_pf'),
    '$s'    : EsilOperator(pop_count=1, internal_name='esil_sf'),
    '$o'    : EsilOperator(pop_count=1, internal_name='esil_of'),
    '$ds'   : EsilOperator(pop_count=0, internal_name='esil_ds'),
    '$jt'   : EsilOperator(pop_count=0, internal_name='esil_jt'),
    '$js'   : EsilOperator(pop_count=0, internal_name='esil_js'),
    '$r'    : EsilOperator(pop_count=0, internal_name='esil_rs'),
    '$$'    : EsilOperator(pop_count=0, internal_name='esil_address'),
    '=='    : EsilOperator(pop_count=2, internal_name='esil_cmp'),
    '<'     : EsilOperator(pop_count=2, internal_name='esil_smaller'),
    '>'     : EsilOperator(pop_count=2, internal_name='esil_bigger'),
    '<='    : EsilOperator(pop_count=2, internal_name='esil_smaller_equal'),
    '>='    : EsilOperator(pop_count=2, internal_name='esil_bigger_equal'),
    '?{'    : EsilOperator(pop_count=1, internal_name='esil_if'),
    '<<'    : EsilOperator(pop_count=2, internal_name='esil_lsl'),
    '<<='   : EsilOperator(pop_count=2, internal_name='esil_lsleq'),
    '>>'    : EsilOperator(pop_count=2, internal_name='esil_lsr'),
    '>>='   : EsilOperator(pop_count=2, internal_name='esil_lsreq'),
    '>>>>'  : EsilOperator(pop_count=2, internal_name='esil_asr'),
    '>>>>=' : EsilOperator(pop_count=2, internal_name='esil_asreq'),
    '>>>'   : EsilOperator(pop_count=2, internal_name='esil_ror'),
    '<<<'   : EsilOperator(pop_count=2, internal_name='esil_rol'),
    '&'     : EsilOperator(pop_count=2, internal_name='esil_and'),
    '&='    : EsilOperator(pop_count=2, internal_name='esil_andeq'),
    '}'     : EsilOperator(pop_count=0, internal_name='esil_nop'),
    '}{'    : EsilOperator(pop_count=0, internal_name='esil_nop'),
    '|'     : EsilOperator(pop_count=2, internal_name='esil_or'),
    '|='    : EsilOperator(pop_count=2, internal_name='esil_oreq'),
    '!'     : EsilOperator(pop_count=1, internal_name='esil_neg'),
    '!='    : EsilOperator(pop_count=1, internal_name='esil_negeq'),
    '='     : EsilOperator(pop_count=2, internal_name='esil_eq'),
    ':='    : EsilOperator(pop_count=2, internal_name='esil_weak_eq'),
    '*'     : EsilOperator(pop_count=2, internal_name='esil_mul'),
    '*='    : EsilOperator(pop_count=2, internal_name='esil_muleq'),
    '^'     : EsilOperator(pop_count=2, internal_name='esil_xor'),
    '^='    : EsilOperator(pop_count=2, internal_name='esil_xoreq'),
    '+'     : EsilOperator(pop_count=2, internal_name='esil_add'),
    '+='    : EsilOperator(pop_count=2, internal_name='esil_addeq'),
    '++'    : EsilOperator(pop_count=1, internal_name='esil_inc'),
    '++='   : EsilOperator(pop_count=1, internal_name='esil_inceq'),
    '-'     : EsilOperator(pop_count=2, internal_name='esil_sub'),
    '-='    : EsilOperator(pop_count=2, internal_name='esil_subeq'),
    '--'    : EsilOperator(pop_count=1, internal_name='esil_dec'),
    '--='   : EsilOperator(pop_count=1, internal_name='esil_deceq'),
    '/'     : EsilOperator(pop_count=2, internal_name='esil_div'),
    '/='    : EsilOperator(pop_count=2, internal_name='esil_diveq'),
    '%'     : EsilOperator(pop_count=2, internal_name='esil_mod'),
    '%='    : EsilOperator(pop_count=2, internal_name='esil_modeq'),
    '=[]'   : EsilOperator(pop_count=2, internal_name='esil_poke'),
    '=[1]'  : EsilOperator(pop_count=2, internal_name='esil_poke1'),
    '=[2]'  : EsilOperator(pop_count=2, internal_name='esil_poke2'),
    '=[3]'  : EsilOperator(pop_count=2, internal_name='esil_poke3'),
    '=[4]'  : EsilOperator(pop_count=2, internal_name='esil_poke4'),
    '=[8]'  : EsilOperator(pop_count=2, internal_name='esil_poke8'),
    '=[16]' : EsilOperator(pop_count=2, internal_name='esil_poke16'),
    '|=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_oreq'),
    '|=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_oreq1'),
    '|=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_oreq2'),
    '|=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_oreq4'),
    '|=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_oreq8'),
    '^=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_xoreq'),
    '^=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_xoreq1'),
    '^=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_xoreq2'),
    '^=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_xoreq4'),
    '^=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_xoreq8'),
    '&=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_andeq'),
    '&=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_andeq1'),
    '&=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_andeq2'),
    '&=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_andeq4'),
    '&=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_andeq8'),
    '+=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_addeq'),
    '+=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_addeq1'),
    '+=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_addeq2'),
    '+=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_addeq4'),
    '+=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_addeq8'),
    '-=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_subeq'),
    '-=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_subeq1'),
    '-=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_subeq2'),
    '-=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_subeq4'),
    '-=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_subeq8'),
    '%=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_modeq'),
    '%=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_modeq1'),
    '%=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_modeq2'),
    '%=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_modeq4'),
    '%=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_modeq8'),
    '/=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_diveq'),
    '/=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_diveq1'),
    '/=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_diveq2'),
    '/=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_diveq4'),
    '/=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_diveq8'),
    '*=[]'  : EsilOperator(pop_count=2, internal_name='esil_mem_muleq'),
    '*=[1]' : EsilOperator(pop_count=2, internal_name='esil_mem_muleq1'),
    '*=[2]' : EsilOperator(pop_count=2, internal_name='esil_mem_muleq2'),
    '*=[4]' : EsilOperator(pop_count=2, internal_name='esil_mem_muleq4'),
    '*=[8]' : EsilOperator(pop_count=2, internal_name='esil_mem_muleq8'),
    '++=[]' : EsilOperator(pop_count=1, internal_name='esil_mem_inceq'),
    '++=[1]': EsilOperator(pop_count=1, internal_name='esil_mem_inceq1'),
    '++=[2]': EsilOperator(pop_count=1, internal_name='esil_mem_inceq2'),
    '++=[4]': EsilOperator(pop_count=1, internal_name='esil_mem_inceq4'),
    '++=[8]': EsilOperator(pop_count=1, internal_name='esil_mem_inceq8'),
    '--=[]' : EsilOperator(pop_count=1, internal_name='esil_mem_deceq'),
    '--=[1]': EsilOperator(pop_count=1, internal_name='esil_mem_deceq1'),
    '--=[2]': EsilOperator(pop_count=1, internal_name='esil_mem_deceq2'),
    '--=[4]': EsilOperator(pop_count=1, internal_name='esil_mem_deceq4'),
    '--=[8]': EsilOperator(pop_count=1, internal_name='esil_mem_deceq8'),
    '<<=[]' : EsilOperator(pop_count=2, internal_name='esil_mem_lsleq'),
    '<<=[1]': EsilOperator(pop_count=2, internal_name='esil_mem_lsleq1'),
    '<<=[2]': EsilOperator(pop_count=2, internal_name='esil_mem_lsleq2'),
    '<<=[4]': EsilOperator(pop_count=2, internal_name='esil_mem_lsleq4'),
    '<<=[8]': EsilOperator(pop_count=2, internal_name='esil_mem_lsleq8'),
    '>>=[]' : EsilOperator(pop_count=2, internal_name='esil_mem_lsreq'),
    '>>=[1]': EsilOperator(pop_count=2, internal_name='esil_mem_lsreq1'),
    '>>=[2]': EsilOperator(pop_count=2, internal_name='esil_mem_lsreq2'),
    '>>=[4]': EsilOperator(pop_count=2, internal_name='esil_mem_lsreq4'),
    '>>=[8]': EsilOperator(pop_count=2, internal_name='esil_mem_lsreq8'),
    '[]'    : EsilOperator(pop_count=1, internal_name='esil_peek'),
    '[*]'   : EsilOperator(pop_count=0, internal_name='esil_peek_some'),
    '=[*]'  : EsilOperator(pop_count=0, internal_name='esil_poke_some'),
    '[1]'   : EsilOperator(pop_count=1, internal_name='esil_peek1'),
    '[2]'   : EsilOperator(pop_count=1, internal_name='esil_peek2'),
    '[3]'   : EsilOperator(pop_count=1, internal_name='esil_peek3'),
    '[4]'   : EsilOperator(pop_count=1, internal_name='esil_peek4'),
    '[8]'   : EsilOperator(pop_count=1, internal_name='esil_peek8'),
    '[16]'  : EsilOperator(pop_count=1, internal_name='esil_peek16'),
    'STACK' : EsilOperator(pop_count=0, internal_name='r_anal_esil_dumpstack'),
    'REPEAT': EsilOperator(pop_count=2, internal_name='esil_repeat'),
    'POP'   : EsilOperator(pop_count=1, internal_name='esil_pop'),
    'TODO'  : EsilOperator(pop_count=0, internal_name='esil_todo'),
    'GOTO'  : EsilOperator(pop_count=1, internal_name='esil_goto'),
    'BREAK' : EsilOperator(pop_count=0, internal_name='esil_break'),
    'CLEAR' : EsilOperator(pop_count=0, internal_name='esil_clear'),
    'DUP'   : EsilOperator(pop_count=0, internal_name='esil_dup'),
    'NUM'   : EsilOperator(pop_count=1, internal_name='esil_num'),
    'SWAP'  : EsilOperator(pop_count=2, internal_name='esil_swap'),
    'TRAP'  : EsilOperator(pop_count=0, internal_name='esil_trap'),
    'BITS'  : EsilOperator(pop_count=0, internal_name='esil_bits'),
    'SETJT' : EsilOperator(pop_count=1, internal_name='esil_set_jump_target'),
    'SETJTS': EsilOperator(pop_count=1, internal_name='esil_set_jump_target_set'),
    'SETD'  : EsilOperator(pop_count=1, internal_name='esil_set_delay_slot'),
    '?{'    : EsilOperator(pop_count=0, internal_name='augmented_loop_begin'),
    '}'     : EsilOperator(pop_count=0, internal_name='augmented_loop_end'),
    'seq'   : EsilOperator(pop_count=2, internal_name='augmented_sequence'),
    'any'   : EsilOperator(pop_count=0, internal_name='augmented_wildcard'),
}

''' esil examples:
mov dword [rbp - 4], 0; 0,0x4,rbp,-,=[4]
cmp dword [rbp - 4], 0; 0,0x4,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,31,$s,sf,:=,31,$o,of,:=
jne 0x45364a          ; zf,!,?{,4535882,rip,=,}
'''

class EsilCommand:
    def __init__(self, cmd: str):
        self.cmd = cmd

    @property
    def is_operator(self) -> bool:
        return self.cmd in esil_operators

    @property
    def pop_count(self) -> int:
        return esil_operators[self.cmd].pop_count

    @property
    def is_integer(self) -> bool:
        with suppress(ValueError):
            if self.cmd.startswith('0x'):
                return isinstance(int(self.cmd, 16), int)
            return isinstance(int(self.cmd, 10), int)
        return False

    @property
    def is_variable(self) -> bool:
        return not (self.is_operator or self.is_integer)

    @property
    def is_sequence(self) -> bool:
        return self.cmd == 'seq'

    @property
    def is_wildcard(self) -> bool:
        return self.cmd == 'any'

    @property
    def internal_name(self) -> str:
        return esil_operators[self.cmd].internal_name

class EsilExpressionTreeNode(EsilCommand):
    def __init__(self, cmd: str, op1=None, op2=None):
        super(EsilExpressionTreeNode, self).__init__(cmd)
        self.op1 = op1
        self.op2 = op2

    def __repr__(self):
        if self.is_sequence:
            return f'{self.op2},{self.op1}'
        elif self.is_wildcard:
            return f'any'
        elif not self.is_operator or self.pop_count == 0:
            return f'{self.cmd}'
        elif self.pop_count == 1:
            return f'{self.op1},{self.cmd}'
        elif self.pop_count == 2:
            return f'{self.op2},{self.op1},{self.cmd}'
        else:
            return 'UNKNOWN'

    def __eq__(self, other):
        if isinstance(other, EsilExpressionTreeNode):
            if self.is_wildcard or other.is_wildcard:
                return True
            elif self.is_leaf and other.is_leaf:
                return self.cmd == other.cmd
            return (self.cmd == other.cmd
                    and self.op1 == other.op1
                    and self.op2 == other.op2)

    def __hash__(self):
        return hash(self.__repr__())

    @property
    def is_leaf(self) -> bool:
        return not (self.op1 or self.op2)

class EsilExpressionTree:
    def __init__(self, expr, external_analyses=dict({})):
        self._expr = expr
        self._stack = list()
        self.analyses = AnalysisEngine(external_analyses)
        self.root = None
        self._parse()

    def __repr__(self):
        return  f'<EsilExpressionTree {self.root}>'

    def __str__(self):
        return str(self.root)

    def __eq__(self, other):
        if isinstance(other, EsilExpressionTree):
            return self.root == other.root
        else:
            raise Exception("Operands must be of the same type.")

    def _parse(self):
        self._items = self._expr.split(',')
        self.analyses.init_analyses()

        while self._items:
            cmd = EsilCommand(self._items.pop(0))
            logger.debug(f'Next item: {cmd.cmd}')

            if not cmd.is_operator or cmd.pop_count == 0:
                node = EsilExpressionTreeNode(cmd.cmd)

            elif cmd.pop_count == 1:
                op1 = self._stack.pop()
                node = EsilExpressionTreeNode(cmd.cmd, op1)

            elif cmd.pop_count == 2:
                op1 = self._stack.pop()
                op2 = self._stack.pop()
                node = EsilExpressionTreeNode(cmd.cmd, op1, op2)

            else:
                raise Exception("Parsing failed.")

            self.analyses.run(node)
            self._stack.append(node)
            logger.debug(f'Pushed {node}')

        while len(self._stack) > 1:
            op1 = self._stack.pop()
            op2 = self._stack.pop()
            sequence_node = EsilExpressionTreeNode('seq', op1, op2)
            self._stack.append(sequence_node)

        self.root = self._stack.pop()
        self.analyses.fini_analyses()

    def search(self, subtree):
        if isinstance(subtree, str):
            subtree = EsilExpressionTree(subtree).root
        elif isinstance(subtree, EsilExpressionTree):
            subtree = subtree.root

        if isinstance(subtree, EsilExpressionTreeNode):
            return self._search_subtree(self.root, subtree)
        else:
            raise Exception('Subtree type not recognized.')

    def _search_subtree(self, root, subtree):
        if root is None:
            return None
        elif root == subtree:
            return root

        return (self._search_subtree(root.op2, subtree) or
                self._search_subtree(root.op1, subtree))
