import math
import collections

class NaiveBayes:
    def __init__(self):
        self.priors = {}
        self.likelihoods = {}

    def train(self, data):
        # data = [({f1:0.1, f2:3}, "malware"), ...]
        cls_count = collections.Counter(lbl for _, lbl in data)
        total = sum(cls_count.values())
        self.priors = {c: math.log(n/total) for c, n in cls_count.items()}
        
        feats = {c: collections.defaultdict(list) for c in cls_count}
        for feats_dict, lbl in data:
            for k, v in feats_dict.items():
                feats[lbl][k].append(v)
        
        for c in feats:
            self.likelihoods[c] = {k: (sum(vals)/len(vals), 1.0)
                                   for k, vals in feats[c].items()}

    def predict(self, feats_dict):
        def log_gauss(x, mu, sigma):
            return -0.5*math.log(2*math.pi*sigma**2) - ((x-mu)**2)/(2*sigma**2)
        
        scores = {}
        for c, prior in self.priors.items():
            s = prior
            for k, x in feats_dict.items():
                if k in self.likelihoods[c]:
                    mu, sigma = self.likelihoods[c][k]
                    s += log_gauss(x, mu, sigma)
            scores[c] = s
        return max(scores, key=scores.get)
