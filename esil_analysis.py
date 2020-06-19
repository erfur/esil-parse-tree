from types import SimpleNamespace

class Analysis:
    def init(self):
        pass

    def node_pass(self, node):
        pass

    def fini(self):
        pass

class MemoryWriteCatcher(Analysis):
    mem_write_operators = frozenset({'=[]', '=[1]', '=[4]', '=[2]', '=[8]'})

    def init(self):
        self.mem_writes = dict()

    def node_pass(self, node):
        if node.cmd in self.mem_write_operators:
            self.mem_writes[node.op1] = node.op2

class MemoryReadCatcher(Analysis):
    mem_read_operators = frozenset({'[]', '[1]', '[2]', '[4]', '[8]'})

    def init(self):
        self.mem_reads = list()

    def node_pass(self, node):
        if node.cmd in self.mem_read_operators:
            self.mem_reads.append(node.op1)

class CompareCatcher(Analysis):
    def init(self):
        self.cmps = list()

    def node_pass(self, node):
        if node.cmd == "==":
            self.cmps.append(node)

class AnalysisEngine:
    def __init__(self, external_analyses=dict({})):
        self.analyses = dict({'memory_read_catcher':MemoryReadCatcher(),
                              'memory_write_catcher':MemoryWriteCatcher(),
                              'compare_catcher':CompareCatcher()})

        self.add_analyses(**external_analyses)
        self.__dict__ = self.analyses

    def init_analyses(self):
        for analysis in self.__dict__.values():
            analysis.init()

    def add_analyses(self, **kwargs):
        for k, v in kwargs.items():
            self.__dict__.__setitem__(k, v)

    def run(self, node):
        for analysis in self.__dict__.values():
            analysis.node_pass(node)

    def fini_analyses(self):
        for analysis in self.__dict__.values():
            analysis.fini()
