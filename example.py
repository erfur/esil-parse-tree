import r2pipe
import sys
import logging

from esil import EsilExpressionTree

logger = logging.getLogger('iopnuke')
logging.basicConfig()
logger.setLevel(logging.INFO)

class BasicBlock:
    def __init__(self, info, instrs):
        self.info = info
        self.instrs = instrs

    @property
    def addr(self):
        return self.info['addr']

class Function:
    def __init__(self, r2, addr):
        self.r2 = r2
        self.addr = addr

    @property
    def bbs(self):
        return list([BasicBlock(bb, self.r2.get_bb_instrs(bb['addr']))
                     for bb in self.r2.get_fcn_bbs(self.addr)])

class Radare2SimpleApi:
    def __init__(self, r2):
        self._r2 = r2

    def get_fcn_bbs(self, addr):
        return self._r2.cmdj(f'abj @{addr}')

    def get_bb_instrs(self, addr):
        return self._r2.cmdj(f'pdbj @{addr}')

    def get_opcodes(self, addr, count=1):
        return self._r2.cmdj('f aoj {count} @{addr}')

    def patch_nop(self, addr):
        return self._r2.cmd(f'wao nop @{addr}')

    def patch_jmp(self, addr):
        return self._r2.cmd(f'wao nocj @{addr}')

class IOPnuke:
    def __init__(self, r2, addr):
        self.function = Function(Radare2SimpleApi(r2), addr)

    def run(self):
        for bb in self.function.bbs:
            mem_writes = dict()
            cmps = list()
            for instr in bb.instrs:
                et = EsilExpressionTree(instr['esil'])
                for address, write in et.analyses.memory_write_catcher.mem_writes.items():
                    mem_writes[address] = write
                cmps += et.analyses.compare_catcher.cmps

                if et.search('zf,?{,any,rip,=,}') or et.search('zf,!,?{,any,rip,=,}'):
                    logger.info(f"je|jne detected! 0x{instr['offset']:x}, last cmp: {cmps[-1]}")
                # TODO eliminate invariant opaque predicate if exists

    def is_invariant_cmp(self, node, mem_writes):
        return (node.op2.is_integer and
                node.op1.op1 in mem_writes and
                mem_writes[node.op1.op1].is_integer)

class UnusedStackNuke:
    def __init__(self, r2, addr):
        self.function = Function(Radare2SimpleApi(r2), addr)

    def run(self):
        stack_var_writes = dict()
        stack_var_reads = list()
        for bb in self.function.bbs:
            for instr in bb.instrs:
                et = EsilExpressionTree(instr['esil'])
                for address, value in et.analyses.memory_write_catcher.mem_writes.items():
                    if not address.is_leaf and address.op1.cmd == "rbp":
                        logger.info(f'memory write {address} <- {value}')
                        stack_var_writes[address] = instr['offset']
                for mem_read in et.analyses.memory_read_catcher.mem_reads:
                    if not address.is_leaf and address.op1.cmd == "rbp":
                        stack_var_reads.append(mem_read)

        for mem_write in stack_var_writes:
            if mem_write not in stack_var_reads:
                logger.info(f'Found unused stack var at 0x{stack_var_writes[mem_write]:x}')
                self.function.r2.patch_nop(stack_var_writes[mem_write])

if __name__ == '__main__':
    r2 = r2pipe.open()
    r2.cmd('e io.cache=True')

    if len(sys.argv) > 1:
        iop = IOPnuke(r2, sys.argv[1])
    else:
        iop = IOPnuke(r2, int(r2.cmd('s'), 16))
    iop.run()

    if len(sys.argv) > 1:
        usn = UnusedStackNuke(r2, sys.argv[1])
    else:
        usn = UnusedStackNuke(r2, int(r2.cmd('s'), 16))
    usn.run()
