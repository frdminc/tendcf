# Must fail by default: builtins.exec exists only with
# allow-unsafe-native-code-during-evaluation.
builtins.exec [ "/bin/echo" "1" ]
