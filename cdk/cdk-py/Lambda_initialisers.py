## This stack creates two lambda functions. One Lambda function initialises the 


from aws_cdk import (
  Stack,
  aws_lambda as _lambda, # Import the Lambda module
  CfnOutput # Import CfnOutput
)
from constructs import Construct

class HelloCdkStack(Stack):

  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Define the Lambda function resource
    my_function = _lambda.Function(
        self, "HelloWorldFunction", 
        runtime = _lambda.Runtime.NODEJS_20_X, # Provide any supported Node.js runtime
        handler = "index.handler",
        code = _lambda.Code.from_inline(
        """
        exports.handler = async function(event) {
          return {
            statusCode: 200,
            body: JSON.stringify('Hello World!'),
          };
        };
        """
        ),
    )
        # Define the Lambda function URL resource
    my_function_url = my_function.add_function_url(
        auth_type = _lambda.FunctionUrlAuthType.AWS_IAM,
        )
    # Define a CloudFormation output for your URL
    CfnOutput(self, "myFunctionUrlOutput", value=my_function_url.url)