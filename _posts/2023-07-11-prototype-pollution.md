---
title: Understanding prototype pollution
published: true
---

## What is a prototype?

To comprehend prototype pollution, it is crucial to understand the concept of a prototype. So, let's dive right into it. A prototype is a mechanism that allows objects to inherit features, properties, and various kinds of data from one another. Let me illustrate this with an example:

```js
const programmingLanguages = {
  coolOne: "Javascript",
  godHelpMe: "APL",
};

Object.prototype.bestOne = "Haskell";
```

![image](https://github.com/renansj/renansj.github.io/assets/5496098/e049486c-ff7e-4487-b18e-9f78b710ed07)


In this example, the `programmingLanguages` object initially only has the properties `coolOne` and `godHelpMe`. However, we then utilize the Object prototype to add another property, `bestOne`, which is inherited by `programmingLanguages` even after its creation. This mechanism is not limited to properties alone; it also applies to functions. In the previous example, if we try to access the `bestOne` property within the `programmingLanguages` object, it will have inherited this property:

```javascript
console.log(programmingLanguages.bestOne); // The output will be Haskell
```

Once you define a property in the Object prototype, all objects derived from Object will also possess that property, unless they already have their own property with the same name. It's important to note that each type has its own prototype. For example, strings inherit from `String.prototype`, and `String.prototype` is derived from `Object.prototype`. In fact, almost all objects inherit from `Object.prototype`, as it serves as the base for all other objects and types.

Objects also have a `__proto__` property, which is an internal property that points to their own prototype.

## What is prototype pollution?

Prototype pollution is a vulnerability in JavaScript that allows an attacker to manipulate object prototypes, enabling them to add arbitrary properties and functions to global objects. These added properties can then be inherited by user-defined objects, resulting in unexpected behavior, privilege escalation, and, in some cases, remote code execution.

## How do these vulnerabilities occur?

These vulnerabilities typically occur when a function recursively merges an object that includes user input properties with an existing object. This enables the attacker to inject a property called `__proto__` along with other properties. When this `__proto__` property is recursively merged, it may be assigned to the object's prototype instead of the intended target object. As a result, an attacker can exploit this behavior by assigning harmful values to properties, which can be used in the application in a dangerous manner. Once polluted, the object and its derived objects inherit the injected properties, allowing the attacker to exploit this behavior to their advantage.

## Server side impact example

Let's see how this vulnerability can escalate privilege in a Node.js application using Express and a vulnerable version of the lodash library (4.17.4):

```js
const user = {
  username: "user",
  pass: "supersecretpass",
};

app.post("/address", (req, res) => {
  // Model-like object
  const address = {
    street: "John Doe",
    number: 1337,
    city: "Neverland",
  };

  if (!req.body.street && !req.body.number && !req.body.city) {
    return res.status(400).send("Invalid Payload");
  }

  lodash.merge(address, req.body);
  return res.status(200).send(`Address created: ${JSON.stringify(address)}`);
});

app.get("/admin", (req, res) => {
  if (!user.isAdmin) {
    return res.status(403).send("You're not an admin");
  }
  return res.status(200).send("FLAG{Oh_s0_y0u'r3_th3_h4ck3r}");
});
```

In the code example above, we can only access the `/admin` endpoint if the `isAdmin` property of the user object is true. As we can see, the user object does not have this property, so it is false, and the server responds with `You're not an admin`. But what's the relation of this with prototype pollution?

In fact, we can access the `/admin` endpoint by polluting the payload received in the `/address` endpoint. If we send the following payload:

```json
{
  "street": "John Doe",
  "number": 1337,
  "city": "Neverland",
  "__proto__": {
    "isAdmin": true
  }
}
```

This payload will pollute the user object due to the line `lodash.merge(address, req.body);`. When the function runs, it recursively merges the payload's body, even hitting the `Object.prototype`, and it will be inherited by all derived objects. Therefore, the user object will now have the isAdmin property set to true, and if you try to request the `/admin` endpoint, the flag will be returned.

![image](https://github.com/renansj/renansj.github.io/assets/5496098/1873c103-0500-4bdb-b4f1-4678c7c56ae2)


So, this is an example of privilege escalation using prototype pollution. However, you can also cause unavailability of the target by overwriting the `toString` function, for example:

```json
{
  "street": "John Doe",
  "number": 1337,
  "city": "Neverland",
  "__proto__": {
    "toString": "I guess you're going to stop working"
  }
}
```

## Preventing prototype pollution

One of the easiest ways to prevent prototype pollution is by sanitizing the keys before merging them with other objects. This helps prevent attackers from injecting any references to the object prototype. It's important to note that sanitizing only the `__proto__` key will not be sufficient. There are other ways to accomplish this, such as using constructors or employing obfuscation techniques if your validation is weak, among others. However, a better approach to prevention is to freeze the `Object.prototype` like this:

```js
Object.freeze(Object.prototype);
```

This ensures that the properties of `Object.prototype` cannot be modified or added to the prototype.

## Conclusion

Prototype pollution is a critical vulnerability that can have severe consequences for JavaScript applications. Understanding the concept and taking preventive measures is crucial to ensure the security and integrity of your code. By sanitizing input and freezing the Object.prototype, you can significantly reduce the risk of prototype pollution attacks.

Remember to stay vigilant, follow best practices, and stay informed about emerging security vulnerabilities to protect your applications effectively.

## References

* [PortSwigger](https://portswigger.net/web-security/prototype-pollution)
* [Mozilla Developer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/prototype)
