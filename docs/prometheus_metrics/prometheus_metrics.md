## Prometheus exporter

ProxySQL includes a built in Prometheus exporter. This exporter let's you expose and consume relevant
system metrics through a friendly interface.

For a complete list of all available metrics, see the [Prometheus Metrics](/proxysql/references/prometheus_metrics) reference.

### Admin variables

- admin-restapi_enabled:
    - Description: Enable or disables the metrics endpoint.
    - Default value: `false`
- admin-restapi_port:
    - Description: Port in which metrics endpoint is going to be exposed.
    - Default value: `6070`
- admin-prometheus_memory_metrics_interval:
    - Description: Internal interval in which memory metrics are going to be collected.
    - Default value: 61

### Configuration

ProxySQL is always collecting metrics since startup, but metrics endpoint is disabled by default,
to enable it and expose this metrics you need to log into the admin console and:

<p>
```
SET admin-restapi_enabled='true';

LOAD ADMIN VARIABLES TO RUNTIME;
```
</p>

Optionally you can also change the other default values in case of need:

<p>
```
SET admin-restapi_port='6070';
SET admin-prometheus_memory_metrics_interval='60';

LOAD ADMIN VARIABLES TO RUNTIME;
```
</p>

Or place the following lines in your config file:

```
admin_variables=
{
...
    restapi_enabled=true
    restapi_port=6070
    prometheus_memory_metrics_interval=60
...
}
```

### Important Notes

#### `admin-restapi_port` collision:

Multiple instances of ProxySQL should have different `restapi_ports` otherwise ProxySQL won't
be able to start the service responsible for exposing the metrics endpoint, this will be reflected
in the logs with the following message:

<p>
```
Unable to start 'ProxySQL_RestAPI_Server', port '%port_number%' already in use.\n
```
</p>

In case this event happened, for re-activating the service at runtime, the user should:

1. Switch the service off: `SET admin-restapi_enabled='false'; LOAD ADMIN VARIABLES TO RUNTIME;`.
2. Change the port to a new desired free one: `SET admin-restapi_port='new_free_port_number'`.
3. Switch the service on again: `SET admin-restapi_enabled='false'; LOAD ADMIN VARIABLES TO RUNTIME;`.


#### Performance considerations:

Most of metrics are collected by ProxySQL in each of it's modules in the form of local counters during
regular operation, as it was previously done. In this sense, internal metrics harvest hasn't change at all.

On the other hand, the actual Prometheus counters exposed through the 'RestAPI' or the 'Admin Interface'
are updated 'on-demand', essentially, internal counters are scrapped and exposed when either endpoint is queried.
This is done for all metrics, with the exception of `memory_metrics`, which defines their own internal,
through the 'admin-variable' `admin-prometheus_memory_metrics_interval` due to their higher performance hit.

Metrics polling should be very fast, and shouldn't affect normal ProxySQL operation at all or being noticeable.
With all this, due to the potential increase in size on the Prometheus end of the time series exposed, and
the nature of the metrics being exposed we **do not recommend** sub-second `scrapping_intervals`.

#### Naming:

Prometheus metrics names used by ProxySQL follow several conventions recommended by Prometheus style guide, and are
also verified against `promtool` checker. This ensures that all ProxySQL metrics are compatible with OpenMetrics format.
