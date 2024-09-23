using MilkStore.Core.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public class Category: BaseEntity
    {
        public string CategoryName { get; set; }
        public virtual ICollection<Products> Products { get; set; }
    }
}
