variable "cluster-name" {
  default = "eks-ebl-cluster"
  type    = string
}

 # This data source is included for ease of sample architecture deployment
 # and can be swapped out as necessary.
 data "aws_availability_zones" "available" {
 }

 resource "aws_vpc" "eks_elb_vpc" {
   cidr_block = "10.0.0.0/16"

   tags = {
     "Name"                                      = "eks-ebl-VPC"
     "kubernetes.io/cluster/${var.cluster-name}" = "shared"
   }
 }

 resource "aws_subnet" "eks_ebl_subnet" {
   count = 2

   availability_zone = data.aws_availability_zones.available.names[count.index]
   cidr_block        = "10.0.${count.index}.0/24"
   vpc_id            = aws_vpc.eks_elb_vpc.id

   tags = {
     "Name"                                      = "eks_ebl_subnet"
     "kubernetes.io/cluster/${var.cluster-name}" = "shared"
   }
 }

 resource "aws_internet_gateway" "eks_ebl_ig" {
   vpc_id = aws_vpc.eks_elb_vpc.id

   tags = {
     Name = "terraform-eks-demo"
   }
 }

 resource "aws_route_table" "eks_ebl_route" {
   vpc_id = aws_vpc.eks_elb_vpc.id

   route {
     cidr_block = "0.0.0.0/0"
     gateway_id = aws_internet_gateway.eks_ebl_ig.id
   }
 }

 resource "aws_route_table_association" "eks_ebl_route_assoc" {
   count = 2

   subnet_id      = aws_subnet.eks_ebl_subnet[count.index].id
   route_table_id = aws_route_table.eks_ebl_route.id
 }

 resource "aws_iam_role" "eks_ebl_iam_role_cluster" {
  name = "eks_ebl_iam_role_cluster"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "eks_ebl_cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_ebl_iam_role_cluster.name
}

resource "aws_iam_role_policy_attachment" "eks_ebl_cluster_AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_ebl_iam_role_cluster.name
}

resource "aws_security_group" "eks_ebl_sg" {
  name        = "eks_ebl_cluster"
  description = "Cluster communication with worker nodes"
  vpc_id      = aws_vpc.eks_elb_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks_ebl"
  }
}

# OPTIONAL: Allow inbound traffic from your local workstation external IP
#           to the Kubernetes. You will need to replace A.B.C.D below with
#           your real IP. Services like icanhazip.com can help you find this.
resource "aws_security_group_rule" "eks_ebl_ingress_workstation_https" {
  cidr_blocks       = ["0.0.0.0/32"]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.eks_ebl_sg.id
  to_port           = 443
  type              = "ingress"
}

resource "aws_eks_cluster" "eks_ebl_cluster" {
  name            = var.cluster-name
  role_arn        = aws_iam_role.eks_ebl_iam_role_cluster.arn

  vpc_config {
    security_group_ids = [aws_security_group.eks_ebl_sg.id]
    subnet_ids         = aws_subnet.eks_ebl_subnet.*.id
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_ebl_cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks_ebl_cluster_AmazonEKSServicePolicy
  ]
}

locals {
  kubeconfig = <<KUBECONFIG


apiVersion: v1
clusters:
- cluster:
    server: ${aws_eks_cluster.eks_ebl_cluster.endpoint}
    certificate-authority-data: ${aws_eks_cluster.eks_ebl_cluster.certificate_authority.0.data}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "${var.cluster-name}"
KUBECONFIG
}

output "kubeconfig" {
  value = "${local.kubeconfig}"
}