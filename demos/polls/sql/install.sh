# determine os
unameOut="$(uname -s)"
case "${unameOut}" in
    Darwin*)    pg_cmd="psql -U postgres";;
    *)          pg_cmd="sudo -u postgres psql"
esac

${pg_cmd} -c "DROP DATABASE IF EXISTS aiohttpdemo_polls"
${pg_cmd} -c "DROP ROLE IF EXISTS aiohttpdemo_user"
${pg_cmd} -c "CREATE USER aiohttpdemo_user WITH PASSWORD 'aiohttpdemo_user';"
${pg_cmd} -c "CREATE DATABASE aiohttpdemo_polls ENCODING 'UTF8';"
${pg_cmd} -c "GRANT ALL PRIVILEGES ON DATABASE aiohttpdemo_polls TO aiohttpdemo_user;"

cat sql/create_tables.sql | ${pg_cmd} -d aiohttpdemo_polls -a
cat sql/sample_data.sql | ${pg_cmd} -d aiohttpdemo_polls -a
