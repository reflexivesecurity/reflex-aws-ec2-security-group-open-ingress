# reflex-aws-detect-security-group-open-ingress
A Reflex rule for detecting EC2 Security Groups with open ingress allowed.

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
version: 0.1

providers:
  - aws

measures:
  - reflex-aws-detect-security-group-open-ingress:
      email: "example@example.com"
```

or add it directly to your Terraform:  
```
...

module "reflex-aws-detect-security-group-open-ingress" {
  source           = "github.com/cloudmitigator/reflex-aws-detect-security-group-open-ingress"
  email            = "example@example.com"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-detect-security-group-open-ingress/blob/master/LICENSE) 
