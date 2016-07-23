sudo -u postgres psql -c "DROP DATABASE IF EXISTS aiohttpdemo_polls"
sudo -u postgres psql -c "DROP ROLE IF EXISTS aiohttpdemo_user"
sudo -u postgres psql -c "CREATE USER aiohttpdemo_user WITH PASSWORD 'aiohttpdemo_user';"
sudo -u postgres psql -c "CREATE DATABASE aiohttpdemo_polls ENCODING 'UTF8';" 
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE aiohttpdemo_polls TO aiohttpdemo_user;"

cat sql/create_tables.sql | sudo -u postgres psql -d aiohttpdemo_polls -a 
cat sql/sample_data.sql | sudo -u postgres psql -d aiohttpdemo_polls -a 
