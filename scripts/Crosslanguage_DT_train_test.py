import pandas as pd
import joblib
import datetime
from utilities_functions import *
import time
import psutil
data=pd.read_csv('./Labelled_Dataset.csv',sep=',')
# Train and evaluate performances


start_time = time.time()
process = psutil.Process()
initial_memory = process.memory_info().rss / (1024 ** 2)  # Initial memory usage in MB
performance, hyperparams=evaluation_decision_tree(data)
final_memory = process.memory_info().rss / (1024 ** 2)    # Final memory usage in MB
memory_usage = final_memory - initial_memory
print(f"Memory usage: {memory_usage} MB")
print("--- %s seconds ---" % (time.time() - start_time))

print(hyperparams)

print("Test Precision       : ",round(performance.iloc[-16,0],2),"±",round(performance.iloc[-16,1],2),'%')
print("Test Recall         : ",round(performance.iloc[-15,0],2),"±",round(performance.iloc[-15,1],2),'%')
print("Test F1-Score  : ",round(performance.iloc[-14,0],2),"±",round(performance.iloc[-14,1],2),'%')
print("Test Accuracy  : ",round(performance.iloc[-13,0],2),"±",round(performance.iloc[-13,1],2),'%')
print("Test False Positive (benign packages classified as malicious one) : ",round(performance.iloc[-12,0],0),"±",round(performance.iloc[-12,1],0),'%')
print("Test False Negative (malicious packages classified as benign): ",round(performance.iloc[-11,0],0),"±",round(performance.iloc[-11,1],0),'%')
print("Test True Negative: ",round(performance.iloc[-10,0],0),"±",round(performance.iloc[-10,1],0),'%')
print("Test True Positive: ",round(performance.iloc[-9,0],0),"±",round(performance.iloc[-9,1],0),'%')
print("Test Precision NPM       : ",round(performance.iloc[-8,0],2),"±",round(performance.iloc[-8,1],2),'%')
print("Test Recall NPM        : ",round(performance.iloc[-7,0],2),"±",round(performance.iloc[-7,1],2),'%')
print("Test F1-Score NPM : ",round(performance.iloc[-6,0],2),"±",round(performance.iloc[-6,1],2),'%')
print("Test Accuracy NPM : ",round(performance.iloc[-5,0],2),"±",round(performance.iloc[-5,1],2),'%')
print("Test Precision Pypi       : ",round(performance.iloc[-4,0],2),"±",round(performance.iloc[-4,1],2),'%')
print("Test Recall Pypi        : ",round(performance.iloc[-3,0],2),"±",round(performance.iloc[-3,1],2),'%')
print("Test F1-Score Pypi : ",round(performance.iloc[-2,0],2),"±",round(performance.iloc[-2,1],2),'%')
print("Test Accuracy Pypi  : ",round(performance.iloc[-1,0],2),"±",round(performance.iloc[-1,1],2),'%')

# Now train final model and dump the model

X = data.drop(labels=['Package Repository','Malicious','Package Name'],axis=1).values
Y = data['Malicious'].astype('int').values

classifier_DT =DecisionTreeClassifier(random_state=123,criterion=hyperparams['criterion'],max_depth=hyperparams['max_depth'],max_features=hyperparams['max_features'],min_samples_leaf=hyperparams['min_sample_leaf'],min_samples_split=hyperparams['min_sample_split'])
classifier_DT.fit(X=X, y=Y)


 
# Get current date and time
dt = str(datetime.datetime.now()).split('.')[0].replace(' ','-').replace(":",'_')
# save the file in the current work directory 
joblib_file='./CrossLanguage_DT_'+dt+'.pkl'
joblib.dump(classifier_DT,joblib_file)