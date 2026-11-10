# access-hr-connector

Keeps Access in step with an HR system. Each connector reads starts, leavers and position changes from the HR system and sends them to Access's HR batch API; Access decides what they mean. The service has its own database and uses public crates only.

## What it does

A connector reads the HR system's employee listing, maps each person to one record and pushes the records to `POST /admin/v1/realms/{slug}/hr-sources/{source}/records:batch` in batches of at most 1 000 records. Each batch is an ordinary `idp.hr.import` write: it is drafted, signed with the connector's Instance key and committed like any other administrator write. The connector decides nothing:

- Access reads every record and refuses a bad batch whole.
- A record that did not change writes nothing.
- An HR record selects people for roles only after the realm's domain accepts the HR source for `subject-selection`.

Start and end dates are applied by Access's HR job, not by the connector: a person is activated on their start date and gets a one-use passkey setup invitation, and is suspended on their end date.

Supported HR systems, in the order they ship:

| Vendor | `vendor` | Listing read |
|---|---|---|
| Personio | `personio` | `GET /v1/company/employees` |
| BambooHR | `bamboohr` | custom report as JSON (`id`, `workEmail`, `department`, `jobTitle`, `supervisorEId`, `hireDate`, `terminationDate`, `status`) |
| HiBob | `hibob` | `POST /v1/people/search` |
| Workday | `workday` | Report-as-a-Service report as JSON (`Employee_ID`, `Email_-_Work`, `Supervisory_Organization`, `Business_Title`, `Manager_Employee_ID`, `Hire_Date`, `Termination_Date`, `Worker_Status`) |
| SAP SuccessFactors | `successfactors` | OData v2 `User` (`userId`, `email`, `department`, `title`, `manager/userId`, `hireDate`, `lastDateWorked`, `status`) |
| Kolay İK | `kolayik` | employee listing |
| Logo | `logo` | personnel listing |

A person without an id or a work e-mail address is left out and counted. Each mapping is tested against a scrubbed sample in the shape of the vendor's documented listing in `tests/fixtures/`; live vendor tenants are not part of the tests.

## Running it

Register the source and the connector first (`registerHrSource`, `registerHrConnector`), then start one process per connector. Configuration comes from the environment; credentials and keys are files, never command-line arguments:

| Variable | Meaning |
|---|---|
| `ACCESS_HR_LISTEN` | address to serve `/hr-connector/v1/*` on |
| `ACCESS_HR_DATABASE_URL` | the connector's own PostgreSQL database |
| `ACCESS_HR_CONNECTOR`, `ACCESS_HR_VENDOR`, `ACCESS_HR_REALM`, `ACCESS_HR_SOURCE` | registered connector name, vendor, realm slug, HR source |
| `ACCESS_HR_ACCESS`, `ACCESS_HR_CA` | Access's public origin; PEM roots for Access and the HR system |
| `ACCESS_HR_TOKEN` | file holding the DPoP-bound read token that drafts each write |
| `ACCESS_HR_SIGNING_KEY`, `ACCESS_HR_BASIS` | PKCS#8 Ed25519 Instance key; base64url Anchor its writes are made under |
| `ACCESS_HR_VENDOR_URL`, `ACCESS_HR_VENDOR_METHOD`, `ACCESS_HR_VENDOR_BODY` | the listing request |
| `ACCESS_HR_VENDOR_CREDENTIAL` | file holding the `Authorization` header value for the HR system |
| `ACCESS_HR_EVERY_S` | seconds between runs, at least 300 (default 3600) |

## API

`sdks/openapi/hr-connector-v1.json`:

- `GET /hr-connector/v1/connectors`: the connector and its last run.
- `POST /hr-connector/v1/connectors/{connector}/runs`: run now.
- `GET /hr-connector/v1/connectors/{connector}/runs/{run}`: one run's counts (records read, left out, pushed, refused, batches), never their content.
- `GET /hr-connector/v1/healthz`: whether the database answers and whether the last run reached Access.

## License

Apache-2.0.
