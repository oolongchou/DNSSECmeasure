from Crypto.Hash import MD5
m=MD5.new()
m.update('jay2018')
print m.hexdigest()