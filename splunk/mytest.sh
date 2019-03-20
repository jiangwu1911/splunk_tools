 curl -k -u 'admin:abcd1234' https://192.168.206.212:8089/services/search/jobs/export \
   -d search="search index=app earliest=-4d@d" \
   -d output_mode=json
