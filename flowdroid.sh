OUTPUT=$(java -jar soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar --apkfile=${1} -p ${2} -s FlowDroid/soot-infoflow-android/SourcesAndSinks.txt -o leaks.xml)
echo ${OUTPUT}