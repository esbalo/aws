resource "aws_iam_role" "eks_ebl_iam_role_worker" {
  name = "eks_ebl_iam_role_worker"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

}

resource "aws_iam_role_policy_attachment" "eks_ebl_worker_AAmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_ebl_iam_role_worker.name
}

resource "aws_iam_role_policy_attachment" "eks_ebl_worker_AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_ebl_iam_role_worker.name
}

resource "aws_iam_role_policy_attachment" "eks_ebl_worker_AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_ebl_iam_role_worker.name
}

resource "aws_security_group" "eks_ebl_sg_workers" {
  name        = "eks_ebl_workers"
  description = "Security group for all nodes in the cluster"
  vpc_id      = aws_vpc.eks_elb_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Name"                                      = "eks_ebl"
    "kubernetes.io/cluster/${var.cluster-name}" = "owned"
  }
}

resource "aws_security_group_rule" "eks_ebl_ingress_self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.eks_ebl_sg_workers.id
  source_security_group_id = aws_security_group.eks_ebl_sg_workers.id
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks_ebl_ingress_cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control      plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_ebl_sg_workers.id
  source_security_group_id = aws_security_group.eks_ebl_sg.id
  to_port                  = 65535
  type                     = "ingress"
 }

 resource "aws_security_group_rule" "eks_ebl_ingress_node_https" {
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_ebl_sg.id
  source_security_group_id = aws_security_group.eks_ebl_sg_workers.id
  to_port                  = 443
  type                     = "ingress"
}

 resource "aws_security_group_rule" "eks_ebl_ingress_node_ssh" {
  cidr_blocks              = ["0.0.0.0/0"]
  description              = "Allow workstation connect to nodes by SSH"
  from_port                = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_ebl_sg_workers.id
  to_port                  = 22
  type                     = "ingress"
}

data "aws_ami" "eks_elb_worker" {
   filter {
     name   = "name"
     values = ["amazon-eks-node-${aws_eks_cluster.eks_ebl_cluster.version}-v*"]
   }

   most_recent = true
   owners      = ["602401143452"] # Amazon EKS AMI Account ID
 }

# This data source is included for ease of sample architecture deployment
# and can be swapped out as necessary.
data "aws_region" "current" {
}

# EKS currently documents this required userdata for EKS worker nodes to
# properly configure Kubernetes applications on the EC2 instance.
# We implement a Terraform local here to simplify Base64 encoding this
# information into the AutoScaling Launch Configuration.
# More information: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
locals {
  demo-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.eks_ebl_cluster.endpoint}' --b64-cluster-ca '${aws_eks_cluster.eks_ebl_cluster.certificate_authority[0].data}' '${var.cluster-name}'
USERDATA

}


resource "aws_iam_instance_profile" "eks_ebl_iam_role_worker" {
  name = "eks_ebl_iam_role_worker"
  role = aws_iam_role.eks_ebl_iam_role_worker.name
}

resource "aws_key_pair" "ebl_key" {
  key_name   = "ebl-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbDTfqYwUi9QANFQop9ARSzO3+OFCdjOvEk7p7eJxhfDXmchQhCcoZUT1y+32zcY1IFRjtejs80eEu/0cbkyzlPF1Y1hJNZnEmQDinJQ/CoE6wFriEjo73ZP6FlQgpCo2zVE0vhTAm8npnR1fMKkFoPMpPVrXpytaGhdgJjBkGc5N6kuJdcXDM6p8mwrEiBI7Pz/A7cLmDNxaxrj2LQA3dcGQaiq8/QRIpUw1xlyMzXQCEOmcnkA/jqFpkcaCyOFfpZaDnAt3bO8zXwstHSXtjxvt0JJmGnMl4rVSJdLT8U64hWusdD+FrvWRefsjUb0LM4JQAy8gcHu73tiwVtQID administrator@LTKB062"
}

resource "aws_launch_configuration" "eks_ebl_lc" {
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.eks_ebl_iam_role_worker.name
  image_id                    = data.aws_ami.eks_elb_worker.id
  instance_type               = "t3.micro"
  name_prefix                 = "eks_ebl_worker_"
  security_groups  = [aws_security_group.eks_ebl_sg_workers.id]
  user_data_base64 = base64encode(local.demo-node-userdata)
  key_name      = aws_key_pair.ebl_key.key_name

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "eks_ebl_autoscaling" {
  desired_capacity     = 2
  launch_configuration = aws_launch_configuration.eks_ebl_lc.id
  max_size             = 2
  min_size             = 1
  name                 = "eks_ebl"
  vpc_zone_identifier = aws_subnet.eks_ebl_subnet.*.id

  tag {
    key                 = "Name"
    value               = "eks_ebl"
    propagate_at_launch = true
  }

  tag {
    key                 = "kubernetes.io/cluster/${var.cluster-name}"
    value               = "owned"
    propagate_at_launch = true
  }
}

locals {
  config_map_aws_auth = <<CONFIGMAPAWSAUTH


apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: ${aws_iam_role.eks_ebl_iam_role_worker.arn}
      username: system:node:{{EC2PrivateDNSName}}
      groups:
        - system:bootstrappers
        - system:nodes
CONFIGMAPAWSAUTH

}

output "config_map_aws_auth" {
  value = local.config_map_aws_auth
}
