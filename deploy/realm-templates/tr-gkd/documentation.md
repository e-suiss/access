# GKD documentation template (ÖHY ve BS Tebliği m.22/7)

A template for the institution's own record of its strong customer authentication (GKD) set-up
on Access. Fill in every bracketed field and keep the filled copy with the institution's
information systems documentation. Regulatory conformity is NOT GUARANTEED by this template or
by Access: the legal assessment is the institution's.

## 1. Scope

| Field | Value |
|---|---|
| Institution | [name, licence type and number] |
| Realm | [realm slug and issuer URL] |
| Governing domain | [domain identifier] |
| Realm template applied | `tr-gkd`, on [date], by [operator] (exercise IDs: [list]) |
| Regulatory template installed | `tr-gkd` policy on the governing domain, on [date] (exercise ID: [id]) |
| Payment actions named | [namespace:name, ...] |

## 2. Authentication elements

| Element | Category | How Access realises it | Evidence |
|---|---|---|---|
| Passkey (device-bound) | Possession | WebAuthn credential with user verification, origin-bound | [registration policy, attestation mode] |
| App-controlled factor | Knowledge | Approver key attested in hardware, signs only after the app's own PIN | [approver activation records] |
| SMS code | Activation only | Accepted only to activate the app-controlled factor; refused at sign-in and after a recent SIM change | [SMS settings, SIM signal source] |

Platform biometrics alone, the mother's maiden name and identity card data are not used as
elements.

## 3. Dynamic linking

A payment action of tier CT2 or CT3 needs an authentication that is bound to the payment's own
intent (amount and payee), is at most five minutes old and is used once. Record here:

- the payment actions the domain policy names: [list];
- the authentication issuer the policy accepts: [party];
- how the payment page shows amount and payee to the customer: [description].

## 4. Changes

| Date | Change | Exercise ID | Approved by |
|---|---|---|---|
| [date] | [what changed] | [id] | [name] |

## 5. Responsibilities

| Role | Person | Since |
|---|---|---|
| GKD owner | [name] | [date] |
| Realm administrator | [name] | [date] |
| Information security officer | [name] | [date] |
