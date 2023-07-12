# 05 - Services

## 5.1 - Start Service

### 5.1.1 - Net

`C:\> net start <service_name>`

### 5.1.2 - SCM (Service Control Management)

`C:\> sc [\\<IP>] start <servicesvc>`

### 5.1.3 - WMIC (Windows Management Instrumentation Command Line)

`C:\> wmic service <service_name> call startservice`

## 5.2 - Stop Service

### 5.2.1 - Net

`C:\> net stop <service_name>`

### 5.2.1 - SCM (Service Control Management)

`C:\> sc [\\<IP>] stop <servicesvc>`