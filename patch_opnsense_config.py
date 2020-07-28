import glob
import pickle

for pkl in glob.iglob('pickles/*.pkl'):
    with open(pkl, 'rb') as f:
        pickle.load(f)
