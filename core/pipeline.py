from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ScanContext
    from models.detection import Detection

class Pipeline:
    def __init__(self, analyzers: List[Any]): # Will be a list of Analyzer instances
        self.analyzers = analyzers

    async def run(self, context: 'ScanContext') -> List['Detection']:
        detections = []
        for analyzer in self.analyzers:
            # Each analyzer will take the context and return detections
            analyzer_detections = await analyzer.analyze(context)
            detections.extend(analyzer_detections)
        return detections
