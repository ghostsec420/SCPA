0. to see who is working with the database (hosts and users from where you connected to it)
shell sqlcmd -S localhost -Q "select loginame, hostname from sys.sysprocesses"

1. Display in kmd all databases on the server
shell sqlcmd.exe -S localhost -E -Q "SELECT name FROM master.dbo.sysdatabases;"

With size in megabytes
shell sqlcmd -S localhost -E -Q "SELECT d.name, ROUND(SUM(mf.size) * 8 / 1024, 0) FROM sys.master_files mf INNER JOIN sys.databases d ON d.database_id = mf.database_id WHERE d.database_id > 4 GROUP BY d.name ORDER BY d.name;"

2. Unloading the 100 most saturated tables in the database, the number of rows and the size of the tables on the hard disk
sqlcmd -S localhost -E -Q "USE %databasename% SELECT TOP 100 s.Name AS SchemaName, t.Name AS TableName, p.rows AS RowCounts, CAST(ROUND((SUM(a.total_pages) / 128.00), 2) AS NUMERIC(36, 2)) AS total_MB FROM sys.tables t INNER JOIN sys.indexes i ON t.OBJECT_ID = i.object_id INNER JOIN sys.partitions p ON i.object_id = p.OBJECT_ID AND i.index_id = p.index_id INNER JOIN sys. allocation_units a ON p.partition_id = a.container_id INNER JOIN sys.schemas s ON t.schema_id = s.schema_id GRCHOUP BY t.Name, s.Name, p.Rows ORDER BY RowCounts desc, Total_MB desc;"
2.1.
sqlcmd -S localhost -E -Q "USE %databasename% SELECT TOP 100 s.Name AS SchemaName, t.Name AS TableName, p.rows AS RowCounts, CAST(ROUND((SUM(a.total_pages) / 128.00), 2) AS NUMERIC(36, 2)) AS total_MB FROM sys.tables t INNER JOIN sys.indexes i ON t.OBJECT_ID = i.object_id INNER JOIN sys.partitions p ON i.object_id = p.OBJECT_ID AND i.index_id = p.index_id INNER JOIN sys. allocation_units a ON p.partition_id = a.container_id INNER JOIN sys.schemas s ON t.schema_id = s.schema_id GROUP BY t.Name, s.Name, p.Rows ORDER BY RowCounts desc, Total_MB desc;"

3. Counting rows in a specific table of a specific database
sqlcmd -S localhost -E -Q "select count(*) from %databasename%.dbo.%tablename%;"

4. Unload the first 10 records in a specific table of a specific database
sqlcmd -S localhost -E -Q "select top 10 * from %databasename%.dbo.%tablename%;"
sqlcmd -S localhost -E -Q "use %databasename%; select top 10 * from %tablename%" -W

5. Search by column names in a specific database using %pass% as an example
sqlcmd -S localhost -E -Q "select COLUMN_NAME as 'ColumnName', TABLE_NAME as 'TableName' from %databasename%.INFORMATION_SCHEMA.COLUMNS where COLUMN_NAME like '%pass%';"

6. Dump the contents of specific columns from a specific table into a txt file on the drive (in this example by the numeric value of the table > date
sqlcmd.exe -S localhost -E -Q "select UserKey, EmailAddress, RealName, Phone, FirstName, LastName, CountryName, CreatedDate from %databasename%.dbo.%tablename% where CreatedDate > '2017-11-30';" -W -s"|" -o "C:\temp\123.txt"
FULL >
sqlcmd.exe -S localhost -E -Q "select * from %databasename%.dbo.%tablename%" -W -s"|" -o "C:\Windows\Temp\1.txt"

7. Output all the tables of a particular database
shell sqlcmd -S localhost -E -Q "use %databasename%; exec sp_tables" -W

for remote/other local server change localhost for ip,port
alternatively - localhost,%port% (watch netstat)

If a table or a database is named with 2-3-4 words, it is escaped like this [%databasename/tablename%].

sqlcmd -E -S localhost -Q "BACKUP DATABASE databasename TO DISK='d:\adw.bak'"
